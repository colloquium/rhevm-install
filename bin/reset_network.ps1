# Powershell script to prepare a Windows host for RHEVM and RHEVM-API

$hostname = "CLUSTER-RHEVM"
$workgroup = "ETCLOUD"

$interfacename = "Local Area Connection"
$ipaddress = "10.16.137.103"
$netmask = "255.255.248.0"
$gateway = "10.16.143.254"
$dnsservers = @("10.16.137.252","10.16.255.2","10.16.255.3")
$dnsdomain = "cloud.lab.eng.bos.redhat.com"
$dnssearch = "cloud.lab.eng.bos.redhat.com","lab.bos.redhat.com","corp.redhat.com","redhat.com"


$computer = Get-WmiObject -Class Win32_ComputerSystem
Write-Output $computer

# Rename Host
$computer.Rename($hostname)
$computer.JoinDomainOrWorkgroup($workgroup)

$nic_index = (Get-WmiObject -Class Win32_NetworkAdapter | where {$_.netconnectionid -eq $interfacename}).InterfaceIndex
Write-Output "NIC Index = $nic_index"

$nic = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.InterfaceIndex -eq $nic_index}
Write-Output "NIC = $nic"

$nic.EnableStatic($ipaddress,$netmask)
$nic.SetGateways($gateway)
$nic.SetDNSServerSearchOrder($dnsservers)
$nic.DNSDomainSuffixSearchOrder = $dnssearch
$nic.SetDynamicDNSRegistration($FALSE,$FALSE)

# These two items are independent of the NIC and related only to the TCP/IP service
set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters UseDomainNameDevolution 0x00000000
set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters SearchList $dnssearch

