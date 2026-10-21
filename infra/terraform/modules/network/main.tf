variable "cidr" { type = string }
variable "name" { type = string }
variable "availability_zone" { type = string }
resource "aws_vpc" "lab" {
  cidr_block = var.cidr
  enable_dns_support = true
  enable_dns_hostnames = true
  tags = { Name = var.name, Scope = "synthetic-sandbox" }
}
resource "aws_subnet" "private" {
  vpc_id = aws_vpc.lab.id
  cidr_block = cidrsubnet(var.cidr, 8, 1)
  availability_zone = var.availability_zone
  map_public_ip_on_launch = false
}
resource "aws_security_group" "data" {
  name_prefix = "securefi-private-"
  vpc_id = aws_vpc.lab.id
  description = "No public ingress; add explicit workload-to-data rules after design review"
  tags = { Scope = "synthetic-sandbox" }
}
output "vpc_id" { value = aws_vpc.lab.id }
output "private_subnet_id" { value = aws_subnet.private.id }
