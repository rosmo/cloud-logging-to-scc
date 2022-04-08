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

variable "alerts" {
  type = map(object({
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
  }
}
