data "aws_availability_zones" "availability_zones" {
  state = "available"
}

data "aws_subnet" "subnet" {
  count = length(var.vm_names)
  id    = tolist(var.subnet_id)[count.index % length(var.subnet_id)]
}

data "aws_vpc" "selector" {
  id      = var.vpc_id
}


data "aws_ami" "windows" {
  most_recent = true
  owners = ["self","amazon"] # Canonical

  filter {
    name   = "name"
    values = [var.windows_ami]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}