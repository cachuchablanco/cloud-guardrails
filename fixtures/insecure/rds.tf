# Planted CG-RDS-001 + CG-ENC-001 + CG-SEC-001:
# public, unencrypted, password in source.
resource "aws_db_subnet_group" "app" {
  name       = "insecure-app-db"
  subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  tags       = { Name = "insecure-db-subnets" }
}

resource "aws_db_instance" "app" {
  identifier              = "insecure-app-db"
  engine                  = "postgres"
  engine_version          = "15.4"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "appadmin"
  password                = "ChangeMeNow-LabOnly!"
  db_subnet_group_name    = aws_db_subnet_group.app.name
  vpc_security_group_ids  = [aws_security_group.app.id]
  publicly_accessible     = true
  storage_encrypted       = false
  skip_final_snapshot     = true
  backup_retention_period = 0

  tags = { Name = "insecure-app-db" }
}
