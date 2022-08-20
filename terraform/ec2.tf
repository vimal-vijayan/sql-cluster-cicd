resource "aws_security_group" "allow_tls" {
  name        = "allow_tls_${var.cluster_name}"
  description = "Allow TLS inbound traffic"
  vpc_id      = var.vpc_id

  ingress {
    description = "RDP from VPC"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.sg_cidr]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    from_port   = 5985
    protocol    = "tcp"
    to_port     = 5985
    cidr_blocks = [var.sg_cidr]
    description = "Winrm-Http"
  }

  ingress {
    from_port   = 1433
    protocol    = "tcp"
    to_port     = 1433
    cidr_blocks = [var.sg_cidr]
    description = "MSSQL"
  }

  ingress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = [var.sg_cidr]
    description = "All Traffic for Cluster Creation"
  }

  ingress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = [var.vpc_cidr]
    description = "All Traffic for Cluster Creation"
  }

  ingress {
    from_port   = 0
    protocol    = "tcp"
    to_port     = 65535
    cidr_blocks = [var.vpc_cidr]
    description = "Cross Region VPC"
  }

  ingress {
    from_port   = 1433
    protocol    = "tcp"
    to_port     = 1433
    cidr_blocks = [data.aws_vpc.selector.cidr_block]
    description = "VPC-VPC MSSQL Traffic"
  }

  tags = {
    Name = "allow_tls_${var.cluster_name}"
  }
}

resource "aws_ebs_volume" "xvdh" {
  count             = length(var.vm_names)
  availability_zone = data.aws_subnet.subnet[count.index % length(var.subnet_id)].availability_zone
  size              = var.hDriveSize
  type              = "gp3"

  tags = {
    Name = "xvdh"
  }
}

resource "aws_ebs_volume" "xvdf" {
  count             = length(var.vm_names)
  availability_zone = data.aws_subnet.subnet[count.index % length(var.subnet_id)].availability_zone
  size              = var.fDriveSize
  type              = "gp3"

  tags = {
    Name = "xvdf"
  }
}

resource "aws_ebs_volume" "xvdg" {
  count             = length(var.vm_names)
  availability_zone = data.aws_subnet.subnet[count.index % length(var.subnet_id)].availability_zone
  size              = var.gDriveSize
  type              = "gp3"

  tags = {
    Name = "xvdg"
  }
}

resource "aws_network_interface" "secondary_eni" {
  count             = length(var.vm_names)
  private_ips_count = 1
  //  subnet_id         = var.subnet_id[count.index] == "" ? var.subnet_id[count.index - count.index] : var.subnet_id[count.index]
  //  subnet_id         = var.subnet_id[count.index] == "" ? var.subnet_id[count.index - count.index] : var.subnet_id[(0)]
  subnet_id         = tolist(var.subnet_id)[count.index % length(var.subnet_id)]
  security_groups   = [aws_security_group.allow_tls.id]
}

resource "aws_instance" "sqlNode" {
  count         = length(var.vm_names)
  ami           = data.aws_ami.windows.id
  instance_type = var.instance_type
  key_name      = "sql-test-sr-key"

  //  iam_instance_profile = "DCSSSMAccessRole"
  //  user_data = "${file("../../../packman.ps1 -ComputerName "${var.vm_names[count.index]}" -xvdfVolumeId "${aws_ebs_volume.xvdf[count.index].id}" -xvdfSize "${var.fDriveSize - 10}" -xvdhVolumeId "${aws_ebs_volume.xvdh[count.index].id}" -xvdhSize "${var.hDriveSize - 10 }" -xvdgVolumeId "${aws_ebs_volume.xvdg[count.index].id}" -xvdgSize "${var.gDriveSize - 10}"")}"
  user_data = <<EOF
          <powershell>
          $op = Get-LocalUSer | where-Object Name -eq "tempUser" | Measure
          if ($op.Count -eq 0) {
              $Password = ConvertTo-SecureString "temp@1234@*" -AsPlainText -Force
              New-LocalUser "tempUser" -Password $Password -FullName "tempUser" -Description "Temporary account"
              Add-LocalGroupMember -Group "Administrators" -Member "tempUser"
              Add-LocalGroupMember -Group "Remote Desktop Users" -Member "tempUser"
          }

          #Instal SSM
          write-output "Entering UD script"
          C:\ProgramData\Amazon\EC2-Windows\Launch\Scripts\InitializeInstance.ps1 -Schedule
          write-output "Exiting out"
          Invoke-WebRequest https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe -OutFile C:\SSMAgent_latest.exe
          Start-Process -FilePath C:\SSMAgent_latest.exe -ArgumentList "/S" -Passthru -Wait -NoNewWindow
          sleep 60

          $volumeLogPath = "c:\windows\temp\volumes.log"
          New-Item $volumeLogPath

          $volumeId = "${aws_ebs_volume.xvdf[count.index].id}".replace('-','')
          Add-Content $volumeLogPath "volumeId1=$volumeId"
          $volumeId = "${aws_ebs_volume.xvdh[count.index].id}".replace('-','')
          Add-Content $volumeLogPath "volumeId2=$volumeId"
          $volumeId = "${aws_ebs_volume.xvdg[count.index].id}".replace('-','')
          Add-Content $volumeLogPath "volumeId3=$volumeId"

          $install_file_dir = "C:\ProgramData\PuppetLabs\facter\facts.d\elevated_groups.JSON"
          If(-NOT (Test-Path $install_file_dir))
          {
              ##Puppet Installation
              $domain = 'us.deloitte.com'
              $install_file_dir = "c:\windows\temp\install.ps1"
              [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
              [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };
              $webClient = New-Object System.Net.WebClient;
              $webClient.DownloadFile('https://uspup-cm.us.deloitte.com:8140/packages/current/install.ps1', $install_file_dir);
              New-Item -Path 'C:\ProgramData\PuppetLabs\facter\facts.d\' -ItemType Directory -ErrorAction silentlycontinue
              New-Item -Path 'C:\ProgramData\PuppetLabs\facter\facts.d\elevated_groups.JSON' -ItemType File -ErrorAction silentlycontinue
              set-content C:\ProgramData\PuppetLabs\facter\facts.d\elevated_groups.JSON '{
                "elevated_groups": {
                  "Administrators": [
                    "us\\SG-US SCM CLUSTERING",
                    "US\\SG-US CMDB eDiscovery",
                    "US\\SG-US SCM PM",
                    "US\\SQL Admins",
                    "US\\SQL Support"
                  ]
                }
              }' -ErrorAction silentlycontinue
              if ($null -ne $domain) {
                $hostname = "${var.vm_names[count.index]}".ToLower()
                $certname = "$hostname.$domain"
                & $install_file_dir agent:certname=$certname
              }
              elseif ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq $false) {
                Write-Output "Server is not part of a domain, and a domain was not passed to the task"
              }
              else {
                & $install_file_dir
              }
              Start-Sleep -s 60
              Rename-Computer -NewName "${var.vm_names[count.index]}" -Restart -Force
          }else {
              puppet agent -t
              Restart-Service AmazonSSMAgent
              Get-Service -ComputerName "${var.vm_names[count.index]}" -Name WinRM | Restart-Service
              Enable-PSRemoting
          }
          </powershell>
  EOF

  timeouts {
    create = "60m"
  }
  root_block_device {
    volume_size = 90
    volume_type = "gp3"
  }

  network_interface {
    device_index         = 0
    network_interface_id = length(var.vm_names) == 1 ? aws_network_interface.secondary_eni[(0)].id : aws_network_interface.secondary_eni[count.index].id
  }

  tags = {
    Name = var.vm_names[count.index]
  }
}


data "aws_network_interface" "eni_data" {
  count = length(var.vm_names)
  id    = aws_network_interface.secondary_eni[count.index].id
}

resource "aws_volume_attachment" "ebs_att1" {
  count       = length(var.vm_names)
  device_name = "xvdh"
  volume_id   = aws_ebs_volume.xvdh[count.index].id
  instance_id = aws_instance.sqlNode[count.index].id
}

resource "aws_volume_attachment" "ebs_att2" {
  count       = length(var.vm_names)
  device_name = "xvdf"
  volume_id   = aws_ebs_volume.xvdf[count.index].id
  instance_id = aws_instance.sqlNode[count.index].id
}

resource "aws_volume_attachment" "ebs_att3" {
  count       = length(var.vm_names)
  device_name = "xvdg"
  volume_id   = aws_ebs_volume.xvdg[count.index].id
  instance_id = aws_instance.sqlNode[count.index].id
}

