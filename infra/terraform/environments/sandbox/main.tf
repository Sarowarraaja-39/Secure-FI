terraform {
  required_version = ">= 1.8, < 2.0"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
}
provider "aws" { region = var.region }
variable "region" { type = string }
variable "availability_zone" { type = string }
variable "evidence_bucket" { type = string }
variable "kms_key_arn" { type = string }
module "network" {
  source = "../../modules/network"
  cidr = "10.44.0.0/16"
  name = "securefi-lab"
  availability_zone = var.availability_zone
}
module "evidence" {
  source = "../../modules/evidence"
  bucket_name = var.evidence_bucket
  kms_key_arn = var.kms_key_arn
}
