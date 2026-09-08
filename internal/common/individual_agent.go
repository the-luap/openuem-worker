package common

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

var errIndividualRequest = errors.New("individual agent request denied")

type individualPayload struct {
	data      []byte
	profileID int
	taskIDs   []int
	hardware  *enrollment.HardwareInventory
	recovery  *enrollment.RecoveryRequest
}

func decodeIndividual(data []byte, value any) error {
	if len(data) == 0 || len(data) > 8<<20 {
		return errIndividualRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errIndividualRequest
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errIndividualRequest
	}
	return nil
}

// Decode once, bind all identity fields and serialize the checked value before
// calling existing handlers. Alternate JSON key spellings cannot make validation
// and the eventual handler observe different identities.
func bindIndividualPayload(identity registry.Identity, operation string, data []byte) (*individualPayload, error) {
	if !enrollment.ValidDeviceID(identity.ID) || identity.TenantID <= 0 || identity.SiteID <= 0 {
		return nil, errIndividualRequest
	}
	tenantID, siteID := strconv.Itoa(identity.TenantID), strconv.Itoa(identity.SiteID)
	scopeMatches := func(tenant, site string) bool {
		return (tenant == "" || tenant == tenantID) && (site == "" || site == siteID)
	}
	result := &individualPayload{}
	var value any
	switch operation {
	case "recovery":
		request, err := enrollment.DecodeRecoveryRequest(data, time.Now())
		if err != nil || identity.Platform != "macos" || request.AgentID != identity.ID {
			return nil, errIndividualRequest
		}
		result.recovery = request
		value = request
	case "hardware":
		var request enrollment.HardwareInventory
		if identity.Platform != "macos" || len(data) > 16<<10 || decodeIndividual(data, &request) != nil || request.AgentID != identity.ID {
			return nil, errIndividualRequest
		}
		hardware, err := enrollment.NormalizeHardware(request)
		if err != nil {
			return nil, errIndividualRequest
		}
		result.hardware = &hardware
		value = hardware
	case "report":
		var report openuem.AgentReport
		if decodeIndividual(data, &report) != nil || report.AgentID != identity.ID || !scopeMatches(report.Tenant, report.Site) {
			return nil, errIndividualRequest
		}
		report.Tenant, report.Site = tenantID, siteID
		report.CertificateReady = true
		value = report
	case "agentconfig":
		var request openuem.RemoteConfigRequest
		if decodeIndividual(data, &request) != nil || request.AgentID != identity.ID || !scopeMatches(request.TenantID, request.SiteID) {
			return nil, errIndividualRequest
		}
		request.TenantID, request.SiteID = tenantID, siteID
		value = request
	case "deployresult", "wingetcfg.deploy", "wingetcfg.exclude":
		var report openuem.DeployAction
		if decodeIndividual(data, &report) != nil || report.AgentId != identity.ID || report.PackageId == "" || len(report.PackageId) > 512 {
			return nil, errIndividualRequest
		}
		if operation != "wingetcfg.exclude" && report.Action != "install" && report.Action != "update" && report.Action != "uninstall" {
			return nil, errIndividualRequest
		}
		value = report
	case "wingetcfg.profiles", "ansiblecfg.profiles":
		var request openuem.CfgProfiles
		if decodeIndividual(data, &request) != nil || request.AgentID != identity.ID || request.ProfileID < 0 {
			return nil, errIndividualRequest
		}
		if (operation == "wingetcfg.profiles" && identity.Platform != "windows") || (operation == "ansiblecfg.profiles" && identity.Platform != "macos") {
			return nil, errIndividualRequest
		}
		result.profileID = request.ProfileID
		value = request
	case "wingetcfg.report":
		var report openuem.ProfileReport
		if decodeIndividual(data, &report) != nil || report.AgentID != identity.ID || report.ProfileID <= 0 || len(report.Tasks) > 1000 {
			return nil, errIndividualRequest
		}
		result.profileID = report.ProfileID
		seen := make(map[int]bool)
		for _, task := range report.Tasks {
			if !strings.HasPrefix(task.Name, "task_") {
				return nil, errIndividualRequest
			}
			part := strings.SplitN(strings.TrimPrefix(task.Name, "task_"), "_", 2)[0]
			id, err := strconv.Atoi(part)
			if err != nil || id <= 0 || strconv.Itoa(id) != part || seen[id] {
				return nil, errIndividualRequest
			}
			seen[id] = true
			result.taskIDs = append(result.taskIDs, id)
		}
		value = report
	default:
		return nil, errIndividualRequest
	}
	var err error
	result.data, err = json.Marshal(value)
	return result, err
}

func (w *Worker) SubscribeIndividualAgentQueues() error {
	if w.Model == nil || w.Model.DB == nil || w.NATSConnection == nil {
		return errIndividualRequest
	}
	access, err := registry.NewAccessStore(w.Model.DB)
	if err != nil {
		return err
	}
	handlers := map[string]nats.MsgHandler{
		"report": w.ReportReceivedHandler, "agentconfig": w.AgentConfigHandler, "deployresult": w.DeployResultReceivedHandler,
		"wingetcfg.profiles": w.ApplyWindowsEndpointProfiles, "ansiblecfg.profiles": w.ApplyUnixEndpointProfiles,
		"wingetcfg.deploy": w.WinGetCfgDeploymentReport, "wingetcfg.exclude": w.WinGetCfgMarkPackageAsExcluded, "wingetcfg.report": w.ProfileReportResponseHandler,
	}
	var subscriptions []*nats.Subscription
	requestContext, cancelRequests := context.WithCancel(context.Background())
	var lifecycle sync.Mutex
	var requests sync.WaitGroup
	closed := false
	rollback := func() {
		lifecycle.Lock()
		closed = true
		cancelRequests()
		lifecycle.Unlock()
		for _, subscription := range subscriptions {
			_ = subscription.Unsubscribe()
		}
		requests.Wait()
	}
	for _, operation := range enrollment.Operations() {
		handler := handlers[operation]
		if handler == nil && operation != "hardware" && operation != "recovery" {
			rollback()
			return errIndividualRequest
		}
		subscription, err := w.NATSConnection.QueueSubscribe("uem.v1.agent.*.request."+operation, "openuem-individual-agents", func(message *nats.Msg) {
			lifecycle.Lock()
			if closed {
				lifecycle.Unlock()
				return
			}
			requests.Add(1)
			lifecycle.Unlock()
			defer requests.Done()
			id, actual, err := enrollment.ParseRequestSubject(message.Subject)
			if err != nil || actual != operation || !enrollment.ValidReply(id, message.Reply) {
				return
			}
			deny := func() { _ = message.Respond([]byte(`{"error":"agent request denied"}`)) }
			ctx, cancel := context.WithTimeout(requestContext, 5*time.Second)
			defer cancel()
			identity, err := access.ActiveIdentity(ctx, id)
			if err != nil {
				deny()
				return
			}
			payload, err := bindIndividualPayload(*identity, operation, message.Data)
			if err != nil {
				deny()
				return
			}
			if err = w.Model.AuthorizeIndividualRequest(ctx, *identity, operation, payload.profileID, payload.taskIDs); err != nil {
				deny()
				return
			}
			checked := *message
			checked.Data = payload.data
			if operation == "recovery" {
				if payload.recovery == nil {
					deny()
					return
				}
				reply, err := access.HandleRecovery(ctx, *identity, *payload.recovery)
				if err != nil {
					deny()
					return
				}
				data, err := json.Marshal(reply)
				if err != nil {
					deny()
					return
				}
				_ = message.Respond(data)
				return
			}
			if operation == "hardware" {
				if payload.hardware == nil || access.RecordHardware(ctx, *identity, *payload.hardware) != nil {
					deny()
					return
				}
				data, _ := json.Marshal(enrollment.HardwareReceipt{Version: enrollment.HardwareInventoryVersion, OK: true})
				_ = message.Respond(data)
				return
			}
			if operation == "agentconfig" {
				version := 0
				recoveryVersion := 0
				if identity.Platform == "macos" && access.HardwareReady(ctx) {
					version = enrollment.HardwareInventoryVersion
				}
				if identity.Platform == "macos" && access.RecoveryReady(ctx) {
					recoveryVersion = enrollment.RecoveryVersion
				}
				w.agentConfigHandler(&checked, version, recoveryVersion)
				return
			}
			handler(&checked)
		})
		if err != nil {
			rollback()
			return err
		}
		subscriptions = append(subscriptions, subscription)
		if err = subscription.SetPendingLimits(64, 16<<20); err != nil {
			rollback()
			return err
		}
	}
	if err = w.NATSConnection.FlushTimeout(5 * time.Second); err != nil {
		rollback()
		return err
	}
	if err = w.NATSConnection.LastError(); err != nil {
		rollback()
		return errIndividualRequest
	}
	w.stopIndividualRequests = rollback
	requests.Add(1)
	go func() {
		defer requests.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			ctx, cancel := context.WithTimeout(requestContext, 5*time.Second)
			if access.RecoveryReady(ctx) && access.ExpireRecoveryTasks(ctx) != nil && requestContext.Err() == nil {
				log.Print("[ERROR]: private recovery task maintenance failed")
			}
			cancel()
			select {
			case <-requestContext.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}
