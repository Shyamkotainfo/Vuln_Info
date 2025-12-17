variable "aws_region" {
  description = "AWS Region"
  default     = "us-east-1"
}

variable "service_name" {
  description = "Name of the App Runner Service"
  default     = "vuln-info-backend"
}

variable "ecr_repo_name" {
  description = "Name of the ECR Repository"
  default     = "vuln-info/backend"
}

variable "mongo_uri" {
  description = "MongoDB Connection URI"
  type        = string
  sensitive   = true
}
