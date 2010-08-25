# Install Cygwin and enable the SSH service

$download_dir = "C:\saved\"

# Cygwin information
$cygwin_setup_uri = "http://www.cygwin.com/setup.exe"
$cygwin_setup = $download_dir + "cygwin_setup.exe"
$cygwin_root = "c:\cygwin"
$cygwin_repo_root = $download_dir + "cygwinrepo"
$cygwin_repo_uri = "http://mirrors.kernel.org/sources.redhat.com/cygwin"
$cygwin_packages = "vim,openssl,openssh,wget,zip,unzip"
$cygwin_bat = $cygwin_root + "\Cygwin.bat"
$cygwin_bat_tmp = $download_dir + "Cygwin.bat"

$wc = new-object net.webclient

# ============================================================================
# Install Cygwin
# ============================================================================

$wc.DownloadFile($cygwin_setup_uri, $cygwin_setup)

$interval = 10
$timeout = 600
$starttime = Get-Date
$endtime = $starttime.AddSeconds($timeout)
write-host "Waiting for installation to complete"

& $cygwin_setup --root $cygwin_root --local-package-dir $cygwin_repo_root --site $cygwin_repo_uri --only-site --packages $cygwin_packages --quiet-mode | Out-File C:\saved\cygwin_install.log

write-host "Cygwin install complete: " ([int] ((Get-Date) - $starttime).TotalSeconds) "seconds"
 
# Set the terminal type and user authentication method
copy $cygwin_bat $cygwin_bat_tmp
get-content $cygwin_bat_tmp | foreach-object {$_ -replace "off", "off`nCYGWIN=tty ntsec"} | set-content $cygwin_bat

$env:Path += ";C:\cygwin\bin"
[Environment]::SetEnvironmentVariable("Path", $env:Path, "Machine")

# wait for install to complete.  Invocation of setup.exe is async.
& ($cygwin_root + "\bin\bash.exe") /usr/bin/ssh-host-config --yes --cygwin C:\cygwin --user cyg_server --pwd "24^gold"

# open SSH port in the firewall
$fw = new-object -comObject HNetCfg.FwPolicy2
$sshrule = new-object -comObject HNetCfg.FwRule
$sshrule.Name = "SSHD (Tcp-In)"
$sshrule.Description = "Secure Shell Inbound"
$sshrule.Protocol = 6 # TCP
$sshrule.LocalPorts = 22
$sshrule.Direction = 1 # inbound
$sshrule.Action = 1 # allow
$fw.Rules.Add($sshrule)
$sshrule.Enabled = $true

net start sshd
