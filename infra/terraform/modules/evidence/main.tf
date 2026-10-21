variable "bucket_name" { type = string }
variable "kms_key_arn" { type = string }
resource "aws_s3_bucket" "evidence" {
  bucket = var.bucket_name
  force_destroy = false
  object_lock_enabled = true
  tags = { Scope = "synthetic-evidence-only" }
}
resource "aws_s3_bucket_public_access_block" "deny" {
  bucket = aws_s3_bucket.evidence.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "versioned" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "kms" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_object_lock_configuration" "retention" {
  bucket = aws_s3_bucket.evidence.id
  depends_on = [aws_s3_bucket_versioning.versioned]
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 30
    }
  }
}
resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*",
    Resource = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"],
    Condition = { Bool = { "aws:SecureTransport" = "false" } }
  }] })
}
output "bucket_arn" { value = aws_s3_bucket.evidence.arn }
