#
# Set the server timezone to UTC (360)
# US Eastern = 35
#
$system = get-wmiobject -class Win32_ComputerSystem
$system.CurrentTimeZone = 0 # UTC