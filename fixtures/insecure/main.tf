terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Planted CG-SEC-001: long-term access keys committed in VCS.
# Values are synthetic and do not match AWS key prefixes.
provider "aws" {
  region     = "us-east-1"
  access_key = "EXAMPLEACCESSKEYNOTREAL"
  secret_key = "examplesecretkeynotreal00000000000000"
}
