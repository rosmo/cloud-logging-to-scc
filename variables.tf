variable "organization_id" {
  type        = string
  description = "Organization ID"
}

variable "project_id" {
  type        = string
  description = "Project ID"
}

variable "region" {
  type        = string
  description = "Region to deploy into"
  default     = "europe-west1"
}

variable "source_name" {
  type        = string
  description = "SCC source name"
  default     = "Cloud Logging alerts"
}

variable "source_id" {
  type        = string
  description = "Preconfigured SCC source ID"
  default     = null
}

variable "channel_name" {
  type        = string
  description = "Notification channel name"
  default     = "Cloud Logging alerts"
}

variable "pubsub_topic" {
  type        = string
  description = "Pub/Sub topic name"
  default     = "scc-logging-alerts"
}

variable "function_name" {
  type        = string
  description = "Pubsub2Inbox Cloud Function name"
  default     = "scc-logging-alerts"
}

variable "superadmin_group" {
  type        = string
  description = "Workspace group that contains Super Admins"
  default     = null
  validation {
    condition     = var.superadmin_group == null || substr(var.superadmin_group, 0, 7) == "groups/"
    error_message = "The superadmin group needs to be null or start with groups/."
  }
}

variable "alerts" {
  type = map(object({
    enabled          = bool
    log_filter       = string
    label_extractors = map(string)
    finding          = string
    interval         = string
    severity         = string
    class            = string
  }))
  description = "Log alerts to configure"
  default = {
    serial-port-access = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName="v1.compute.instances.setMetadata"
            protoPayload.metadata.instanceMetadataDelta.addedMetadataKeys="serial-port-enable"
          EOT
      finding          = "SERIAL_PORT_ACCESS_TURNED_ON"
      severity         = "MEDIUM"
      class            = "VULNERABILITY"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    serial-port-connect = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName="google.ssh-serialport.v1.connect"
          EOT
      finding          = "SERIAL_PORT_ACCESS_CONNECT"
      severity         = "MEDIUM"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    suspicious-login = { # Already in ETD
      enabled          = false
      log_filter       = <<EOT
            protoPayload.metadata.event.parameter.name="is_suspicious"
            protoPayload.metadata.event.parameter.boolValue="true"
          EOT
      finding          = "SUSPICIOUS_LOGIN"
      severity         = "HIGH"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    superadmin-login = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.authenticationInfo.principalEmail=%superadmins%
            protoPayload.methodName:"LoginService.loginSuccess"
          EOT
      finding          = "SUPERADMIN_LOGIN"
      severity         = "HIGH"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    superadmin-added-to-group = {
      enabled          = false
      log_filter       = <<EOT
            protoPayload.methodName:"AdminService.addGroupMember"
            protoPayload.metadata.event.parameter.value="%superadmin-group%"
          EOT
      finding          = "SUPERADMIN_ADDED"
      severity         = "CRITICAL"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    workspace-role-granted = {
      enabled          = false
      log_filter       = <<EOT
            protoPayload.methodName:"AdminService.assignRole" OR
            protoPayload.methodName:"AdminService.addPrivilege"
          EOT
      finding          = "WORKSPACE_ROLE_GRANTED"
      severity         = "CRITICAL"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    workspace-settings-changed = {
      enabled          = false
      log_filter       = <<EOT
            protoPayload.methodName:"AdminService.changeApplicationSetting"
          EOT
      finding          = "WORKSPACE_ROLE_GRANTED"
      severity         = "CRITICAL"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    org-admin-added = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName:"SetIamPolicy"
            protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/resourcemanager.organizationAdmin"
          EOT
      finding          = "ORG_ADMIN_ADDED"
      severity         = "CRITICAL"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    service-account-editor-owner = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName:"SetIamPolicy"
            protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
            protoPayload.serviceData.policyDelta.bindingDeltas.member:".gserviceaccount.com"
            (protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner" OR
            protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/editor")
          EOT
      finding          = "SERVICE_ACCOUNT_EDITOR_OWNER"
      severity         = "CRITICAL"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    gcs-bucket-made-public = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName="storage.setIamPermissions" AND
            (protoPayload.serviceData.policyDelta.bindingDeltas.member="allUsers" OR
            protoPayload.serviceData.policyDelta.bindingDeltas.member="allAuthenticatedUsers")
          EOT
      finding          = "BUCKET_MADE_PUBLIC"
      severity         = "CRITICAL"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    org-folder-permissions-set = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName="SetIamPolicy"
            (protoPayload.resourceName:"organizations" OR protoPayload.resourceName:"folder")
          EOT
      finding          = "ORG_FOLDER_POLICY_CHANGED"
      severity         = "HIGH"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    service-account-created = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName:"CreateServiceAccount" OR protoPayload.methodName:"CreateServiceAccountKey" OR
            protoPayload.methodName:"storage.hmacKeys.create"
          EOT
      finding          = "SERVICE_ACCOUNT_ADDED"
      severity         = "MEDIUM"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    ssh-key-uploaded = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName="v1.compute.instances.setMetadata"
            protoPayload.metadata.instanceMetadataDelta.addedMetadataKeys="ssh-keys"
          EOT
      finding          = "SSH_KEY_UPLOADED"
      severity         = "MEDIUM"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    snapshot-created = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName:"compute.disks.createSnapshot"
          EOT
      finding          = "DISK_SNAPSHOT_CREATED"
      severity         = "MEDIUM"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    snapshot-permission-added = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName: "compute.snapshots.setIamPolicy"
            protoPayload.status.code="3"
            protoPayload.status.message="One or more users named in the policy do not belong to a permitted customer."
          EOT
      finding          = "DISK_SNAPSHOT_IAM_ADDED"
      severity         = "MEDIUM"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    drs-violated = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName:"SetIamPolicy"
            severity=ERROR
          EOT
      finding          = "DRS_VIOLATED"
      severity         = "HIGH"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    gcs-vpc-sc-violated = {
      enabled          = true
      log_filter       = <<EOT
            protoPayload.methodName:"storage.objects.create"
            protoPayload.metadata.resourceNames:"buckets"
            protoPayload.metadata.violationReason:"NOT_IN_SAME_SERVICE_PERIMETER"
          EOT
      finding          = "VPCSC_GCS_VIOLATED"
      severity         = "HIGH"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    csts-activation = {
      enabled          = true
      log_filter       = <<EOT
            (protoPayload.methodName:"ServiceManager.ActivateServices"
            protoPayload.authorizationInfo.resource: "services/storagetransfer.googleapis.com") OR
            (protoPayload.methodName="storage.setIamPermissions"
            protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
            protoPayload.serviceData.policyDelta.bindingDeltas.member:"@storage-transfer-service.iam.gserviceaccount.com")
          EOT
      finding          = "STS_PERMISSIONS_ENABLED"
      severity         = "HIGH"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
    vpc-flow-logs-abnormal-ips = {
      enabled          = true
      log_filter       = <<EOT
            resource.type="gce_subnetwork"
            logName:"logs/compute.googleapis.com%2Fvpc_flows"
            NOT (ip_in_net(jsonPayload.connection.dest_ip, "10.0.0.0/8") OR
            ip_in_net(jsonPayload.connection.dest_ip, "8.8.4.0/24"))
          EOT
      finding          = "STS_PERMISSIONS_ENABLED"
      severity         = "HIGH"
      class            = "THREAT"
      label_extractors = {}
      interval         = "300s" # minimum 300s
    }
  }
}
