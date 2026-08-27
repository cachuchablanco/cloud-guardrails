# Planted CG-S3-001 + CG-ENC-001:
# public ACL, public bucket policy, no public-access block, no encryption.
resource "aws_s3_bucket" "public_logs" {
  bucket = "acme-lab-public-logs"
  acl    = "public-read"

  tags = {
    Name = "public-logs"
    env  = "lab"
  }
}

resource "aws_s3_bucket_policy" "public_logs" {
  bucket = aws_s3_bucket.public_logs.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::acme-lab-public-logs/*"
    }
  ]
}
POLICY
}

resource "aws_s3_bucket" "backups" {
  bucket = "acme-lab-backups-open"
  tags   = { Name = "backups", env = "lab" }
}
