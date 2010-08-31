# Set up Red Hat Enterprise Virtualization Management (RHEVM) 2.2 on
# Windows 2008 R2 Standard.
#
# The target system must have:
# 1) OS Installed
# 2) Administrator Password Set
# 3) Activated
# 4) Network identity configured
# 5) Cygwin installed
# 6) SSHD configured, enabled and firewall allowing inbound port 22
#

param([switch] $debug, [switch] $verbose, [switch] $revert, [switch] $dryrun,
      $logfile=$null, $installparts = "all", $checkparts = "all")

if ($logfile) {
  Start-Transcript -Path $logfile
}

$liverun = -not $dryrun

# Global Variables
$wc = new-object net.webclient
$sh = new-object -comObject shell.application

$download_root = "C:\saved\"

# Application Variables
$rhevm_installer_uri = "http://irish.lab.bos.redhat.com/pub/projects/cloud/resources/RHEV22u2/RHEVM_47069.exe"
$rhevm_config_uri = "http://irish.lab.bos.redhat.com/pub/mlamouri/rhevm-install/data/rhevm_2.2u2.iss"

$jre_installer_uri = "http://irish.lab.bos.redhat.com/pub/mlamouri/rhevm-install/data/jre-6u21-windows-x64.exe"
$jrk_file = ($jdk_installer_uri -split "/")[-1]
$jre_path = $download_root + $jdk_file
$jre_event_match = "Java(TM) SE"	
$java_home = "C:\Program Files\Java\jre1.6.0_21"

# Java development kit can't be gotten direct from Oracle so get it from a
# local repository
$jdk_installer_uri = "http://irish.lab.bos.redhat.com/pub/mlamouri/rhevm-install/data/jdk-6u21-windows-x64.exe"
$jdk_file = ($jdk_installer_uri -split "/")[-1]
$jdk_path = $download_root + $jdk_file
$jdk_event_match = "Java(TM) SE Devel"	
$java_home = "C:\Program Files\Java\jdk1.6.0_21"

#$tomcat_uri = "http://mirror.cc.columbia.edu/pub/software/apache/tomcat/tomcat-5/v5.5.30/bin/apache-tomcat-5.5.30.exe"
$tomcat_uri = "http://irish.lab.bos.redhat.com/pub/mlamouri/rhevm-install/data/apache-tomcat-5.5.30.zip"
$tomcat_uri = "http://irish.lab.bos.redhat.com/pub/mlamouri/rhevm-install/data/apache-tomcat-6.0.29-windows-x64.zip"
$tomcat_dname = "CN=cluster-rhevm.cloud.lab.eng.bos.redhat.com, OU=Emerging Technologies (Cloud), O=Red Hat, L=Westford, ST=Massachusetts, C=US"

$jboss_version = "5.1.0.GA"
$jboss_zip = "jboss-" + $jboss_version + "-jdk6.zip"
#$jboss_zip_uri = "http://sourceforge.net/projects/jboss/files/JBoss/JBoss-" + $jboss_version + "/" + $jboss_zip + "/download"
$jboss_zip_uri = "http://irish.lab.bos.redhat.com/pub/mlamouri/rhevm-install/data/" + $jboss_zip

$jboss_dname = "CN=cluster-rhevm.cloud.lab.eng.bos.redhat.com, OU=Emerging Technologies (Cloud), O=Red Hat, L=Westford, ST=Massachusetts, C=US"
#$jboss_service_uri = "http://downloads.jboss.org/jbossnative/2.0.9.GA/jboss-native-2.0.9-windows-x64-ssl.zip"

$jboss_service_uri = "http://irish.lab.bos.redhat.com/pub/mlamouri/rhevm-install/data/jboss-native-2.0.9-windows-x64-ssl.zip"

$rhevm_api_war_uri = "http://repo2.maven.org/maven2/com/redhat/rhevm/api/rhevm-api-powershell-webapp/0.9-milestone3.1/rhevm-api-powershell-webapp-0.9-milestone3.1.war"

# ============================================================================
# Utility functions
# ============================================================================

function debug {
    param ($message)

    if ($debug) { write-host ("DEBUG: " + $message) }
}

function verbose {
    param ($message, [switch] $nonewline)
    
    if ($verbose) {
        if ($nonewline) {
	    write-host -NoNewline $message
        } else {
            write-host $message
        }
    }
}

function error {
    param ($message, $action="exit")

    write-host ("ERROR: " + $message)
    if ($action -eq "exit") { exit }
}

#
# given a zip file name and a folder name, unpack...
#
function unzip {
  param ($zip_file, $target_folder)

  debug "zip file = $zip_file , target_folder = $target_folder"
  $sh = new-object -comObject shell.application

  $zip_folder = $sh.namespace($zip_file)
  if ($liverun) {
      $sh.namespace($target_folder).CopyHere($zip_folder.items(), 4 + 16 + 512)
  }
}

#
#
#
function Install_IIS {

    Import-Module ServerManager
    (Get-Module ServerManager).ExportCmdlets

    verbose "Installing IIS"
    if ($liverun) { Add-WindowsFeature Web-Server }
    verbose "Installing .Net"
    if ($liverun) { Add-WindowsFeature Net-Framework }
}

function Check_IIS {
    # Check that IIS and .Net are installed
    debug "Checking IIS"

    Import-Module ServerManager
    (Get-Module ServerManager).ExportCmdlets

    if ((Get-WindowsFeature -Name "Web-Server") -eq $null) {
        error "Windows Feature 'Web-Server' not installed"
    } else {
        verbose "CHECK: Windows Feature 'Web-Server' installed"
    }

    if ((Get-WindowsFeature -Name "Net-Framework") -eq $null) {
        error "Windows Feature 'Net-Framework' not installed"
    } else {
        verbose "CHECK: Windows Feature 'Net-Framework' installed"
    }
}

#
# depends on $wc and $download_root
#
function Install_RHEVM {
    param ($installer_uri, $config_uri)

    # get the file name from the end of the URI
    $installer_file = ($installer_uri -split "/")[-1]
    $config_file = ($config_uri -split "/")[-1]

    # add the download root
    $installer_path = $download_root + $installer_file
    $config_path = $download_root + $config_file

    verbose "Getting RHEVM installer: $installer_file"
    $wc.DownloadFile($installer_uri, $installer_path)
    verbose "Getting RHEVM configuration: $config_file"
    $wc.DownloadFile($config_uri, $config_path)

    $starttime = Get-Date
    $interval = 3
    $timeout = 600
    $endtime = $starttime.AddSeconds($timeout)

    $cmd = "$installer_path -s -f1$config_path"
    debug "Executing: $cmd"
    verbose "Installing RHEVM: Timeout = $timeout seconds"
    if ($liverun) { 
        & $installer_path -s "-f1$config_path"

        do {
            sleep $interval
            verbose -NoNewline "."
        } until (Get-EventLog Application | where-object { ($_.TimeGenerated -gt $starttime -and $_.EventId -eq 1035 -and $_.Message -match "Red Hat Enterprise Virtualization Manager" -and $_.Message -match "Reconfiguration success or error status: 0") -or ((Get-Date) -gt $endtime) }
        )
        verbose ""
   	verbose ("Elapsed Time: " + ([int] (((Get-Date).Subtract($starttime)).TotalSeconds)) + " Seconds")
       
    }
}

function Check_RHEVM {
    debug "Checking RHEVM"
   
    if ((Get-Service RHEVManager) -eq $null) {
        error "Missing service: RHEVManager"
    } else {
        verbose "CHECK: RHEVManager Service Present"
    }

    if ((Get-Service "MSSQL`$SQLEXPRESS" ) -eq $null) {
        error "Missing service: SQL Server (SQLEXPRESS)"
    } else {
        verbose "CHECK: SQL Server (SQLEXPRESS) Present"
    }
}

function Install_JRE {
    param($jre_installer_uri)

    $jre_installer_file = ($jre_installer_uri -split "/")[-1]
    $jre_installer_path = $download_root + $jre_installer_file
    $jre_installer_log = $download_root + "jre_installer.log"

    $jre_completion_message = "Product Name: Java\(TM\)"

    verbose "Downloading $jre_installer_uri"
    $wc.DownloadFile($jre_installer_uri, $jre_installer_path)

    $starttime = Get-Date
    $interval = 3
    $timeout = 600
    $endtime = $starttime.AddSeconds($timeout)

    debug "Executing: $jre_installer_path /quiet /li $jre_installer_log"
    verbose "Installing JRE: Timeout = $timeout seconds"
    if ($liverun) {    
        & $jre_installer_path /quiet /li $jre_installer_log
        do {
            sleep $interval
            verbose -NoNewline "."
        } until (Get-EventLog Application | where-object { ($_.TimeGenerated -gt $starttime -and $_.EventId -eq 1033 -and $_.Message -match $jre_completion_message) -or ((Get-Date) -gt $endtime) }
        )
        verbose "."
	verbose ("Elapsed Time: " + ([int] (Get-Date).Subtract($starttime).TotalSeconds) + " seconds")

	sleep $interval
        $java_home = (get-childitem "C:\Program Files\Java").FullName
        verbose "JAVA_HOME = $java_home"
        $env:JAVA_HOME = $java_home
        [Environment]::SetEnvironmentVariable("JAVA_HOME", $java_home, "Machine")
        [Environment]::SetEnvironmentVariable("JAVA_HOME", $java_home)

        verbose "JAVA_OPTS = -server"
        $env:JAVA_OPTS = "-server"
        [Environment]::SetEnvironmentVariable("JAVA_OPTS", $env:JAVA_OPTS, "Machine")
        [Environment]::SetEnvironmentVariable("JAVA_OPTS", $evn:JAVA_OPTS)

	verbose "Appending JRE bin to PATH"
	$env:Path += ";$java_home\bin"
	[Environment]::SetEnvironmentVariable("Path", $env:Path, 'Machine')

    }
}

function Install_JDK {
    param($jdk_installer_uri)

    $jdk_installer_file = ($jdk_installer_uri -split "/")[-1]
    $jdk_installer_path = $download_root + $jdk_installer_file
    $jdk_installer_log = $download_root + "jdk_installer.log"

    $jdk_completion_message = "Java\(TM\) SE Development Kit"

    verbose "Downloading $jdk_installer_uri"
    $wc.DownloadFile($jdk_installer_uri, $jdk_installer_path)
    
    $starttime = Get-Date
    $interval = 3
    $timeout = 600
    $endtime = $starttime.AddSeconds($timeout)

    debug "Executing: $jdk_installer_path /quiet /li $jdk_installer_log"
    verbose "Installing JDK: Timeout = $timeout seconds"
    if ($liverun) {    
        & $jdk_installer_path /quiet /li $jdk_installer_log
        do {
            sleep $interval
            verbose -NoNewline "."
        } until (Get-EventLog Application | where-object { ($_.TimeGenerated -gt $starttime -and $_.EventId -eq 1033 -and $_.Message -match $jdk_completion_message) -or ((Get-Date) -gt $endtime) }
        )
        verbose "."
	verbose ("Elapsed Time: " + ([int] (Get-Date).Subtract($starttime).TotalSeconds) + " seconds")

	sleep $interval
        $java_home = (get-childitem "C:\Program Files\Java").FullName
        verbose "JAVA_HOME = $java_home"
        $env:JAVA_HOME = $java_home
        [Environment]::SetEnvironmentVariable("JAVA_HOME", $java_home, "Machine")
        [Environment]::SetEnvironmentVariable("JAVA_HOME", $java_home)

        $env:JAVA_OPTS = "-server"
        [Environment]::SetEnvironmentVariable("JAVA_OPTS", $env:JAVA_OPTS, "Machine")

	verbose "Appending JDK bin to PATH"
	$env:Path += ";$java_home\bin"
	[Environment]::SetEnvironmentVariable("Path", $env:Path, 'Machine')
    }
}

function Check_JDK {
    debug "Checking JDK"

    # JAVA_HOME set?
    if ($env:JAVA_HOME -eq $null) {
        error "JAVA_HOME is not set"
    } else {
        verbose "CHECK: JAVA_HOME=$env:JAVA_HOME"
    }


    # JAVA_HOME present?
    $sh = new-object -comObject shell.application
    if ($sh.NameSpace($env:JAVA_HOME) -eq $null) {
        error "JAVA_HOME directory $env:JAVA_HOME does not exist"
    } else {
        verbose "CHECK: directory $JAVA_HOME exists"
    }

    # JAVA_HOME in the path?
    $plist = $env:Path -split ";"
    if ($plist -contains ($JAVA_HOME + "\bin")) {
        verbose "CHECK: PATH contains JAVA_HOME"
    } else {
        error "PATH does not contain JAVA_HOME: Path = $env:Path"
    }

    # check that javac exists, runs and print the version
}

function Install_Tomcat {
    param($tomcat_zip_uri, $target_dir_name = "C:\")

    $tomcat_zip_file = ($tomcat_uri -split "/")[-1]
    $tomcat_zip_path = $download_root + $tomcat_zip_file


    verbose "Downloading $tomcat_zip_uri"
    $wc.DownloadFile($tomcat_zip_uri, $tomcat_zip_path)

    $sh = new-object -comObject shell.application
    $zip_folder = $sh.namespace($tomcat_zip_path)
    if ($liverun) {
        $sh.namespace($target_dir_name).CopyHere($zip_folder.items(), 4+16+512)
    }
    # get top dir from ZIP file. There's only one by convention
    $tomcat_dir = $zip_folder.items() | foreach {$_.Name}
    $tomcat_root = $target_dir_name + $tomcat_dir

    debug "CATALINA_HOME = $tomcat_root"

    $env:CATALINA_HOME = $tomcat_root
    [Environment]::SetEnvironmentVariable("CATALINA_HOME", $tomcat_root, "Machine")
    return $tomcat_root
}

function Enable_Tomcat_SSL {
    param($tomcat_root, $dname, $keypass="notsecure")

    $tomcat_conf_dir = $tomcat_root + "\conf\"
    # Key Generation Variable
    $keytool = $env:JAVA_HOME + "\bin\keytool.exe"
    $keytype = "RSA"
    $keyalias = "tomcat"
    $keypass = "notsecure"
    $keystore = "ssl.keystore"

    $keyfile = $tomcat_conf_dir + $keystore

    # generate X509 SSL key
    $cmd = "$keytool -genkey -alias $keyalias -keyalg $keytype -keystore $keyfile -keypass $keypass -storepass $keypass -dname '$dname'"
    debug "Executing: $cmd"
    & $keytool -genkey -alias $keyalias -keyalg $keytype -keystore $keyfile -keypass $keypass -storepass $keypass -dname $dname
    # configure service ports:

    $tomcat_server_xml = $tomcat_conf_dir + "server.xml"
    $tomcat_server_xml_orig = $tomcat_server_xml + ".orig"

    ##  Disable cleartext 8080
    ##  Disable AJP 8009
    ##  Enable SSL port 8143
    copy $tomcat_server_xml $tomcat_server_xml_orig

    debug "reading $tomcat_server_xml_orig"

    # Modify the tomcat server.xml to allow SSL only

    $fin = [System.IO.File]::OpenText($tomcat_server_xml_orig)


    # This next is a fairly complicated piece of code to do a fairly simple
    # thing.
    # Comment out the Connectors on port 8080 and 8009
    # Uncomment the Connector on port 8443
    # Add the keystoreFile and keystorePass attributes to the SSL Connector

    $port = $null
    $begin = $false
    $end = $false
    $comment = $false
    $addcomment = $false
    $uncomment = $false

    $out = while ($fin.Peek() -ne -1) {
        $line = $fin.ReadLine()

        if ($line -match "<!--") { $comment = $true }

        if ($line -match "-->") {
            if ($uncomment) { 
                $line = $line -replace "-->", "<!-- -->"
                $uncomment = $false
            }
            $comment = $false
        }

        if ($line -match "<Connector port=`"(\d+)`"") {
            $port = $matches[1]
            $begin = $true

            # Reset the connector protocol
	    $line = $line -replace 'protocol="HTTP/1.1"', 'protocol="org.apache.coyote.http11.Http11Protocol"'

            if ($port -eq "8080" -or $port -eq "8009") {
	        $line =  "    <!--`n" + $line
                $addcomment = $true
            }

            if ($port -eq "8443" -and $comment) {
                $line = "    -->`n" + $line
                $uncomment = $true

                # Add the keystore information
                $line += "`n               keystoreFile=`"conf/ssl.keystore`" keystorePass=`"notsecure`" keyAlias=`"tomcat`"" 
            }
        }

        if ($begin -and $line -match "/>") {
            if ($addcomment) { $line += "`n    -->" }
            $addcomment = $false
            $end = $true
        }

        if ($begin -and $end) {
            $begin = $false
            $end = $false
        }
        $line 
    }
    $fin.Close()

    debug "writing $tomcat_server_xml"

    # Jboss and Tomcat like unix line terminators.  
    # The procedure above writes DOS line terminators.
    # The two lines below convert the file back.
    set-content ($tomcat_server_xml + ".bin") $out
    get-content -Encoding Byte ($tomcat_server_xml + ".bin") | where {$_ -ne 13} | set-content -Encoding Byte $tomcat_server_xml
    remove-item ($tomcat_server_xml + ".bin")

    # Add a firewall rule to allow JBoss access
    debug "adding Tomcat firewall rule"
    $fw = new-object -comObject HNetCfg.FwPolicy2
    $fwrule = new-object -comObject HNetCfg.FwRule
    $fwrule.Name = "Tomcat (Tcp-In)"
    $fwrule.Description = "Tomcat Application Container Inbound Access"
    $fwrule.Protocol = 6 # TCP
    $fwrule.LocalPorts = "8443"
    $fwrule.Direction = 1 # Inbound
    $fwrule.Action = 1 # Allow
    if ($liverun) { $fw.Rules.Add($fwrule) }
    $fwrule.Enabled = $true
}


function Enable_Tomcat_Manager {
    param($userfile = (${env:$CATALINA_HOME} + "\conf\tomcat-users.xml"))

    
}

function Enable_Tomcat_Service {

    # Install the service
    $result = & ${env:CATALINA_HOME}\bin\service.bat install

    write-host $result

    $result[0] -match "Installing the service '(\w+)'"
    $serviceName = $matches[1]

    # Enable the service on boot
    verbose "Enabling $serviceName on startup"
    Set-Service $serviceName -startupType automatic


    # Start the service
    net start $serviceName
}


function Install_JBoss {
    param($jboss_zip_uri, $target_dir_name = "C:\", $bind_address="0.0.0.0", $port_set="ports-01")
    
    # downloads from sourceforge end in /<filaname>/download
    $jboss_zip_file = ($jboss_zip_uri -split "/")[-1]
    $jboss_zip_path = $download_root + $jboss_zip_file

    $jboss_root = $env:JBOSS_HOME

     
    # tell JBoss to use a second set of ports to avoid conflicts with IIS/RHEVM
    $binding_set_prop = "jboss.service.binding.set"
    $binding_set_default = "ports-default"
    $oldmarker = $binding_set_prop + ":" + $binding_set_default
    $newmarker = $binding_set_prop + ":" + $port_set

    verbose "Downloading $jboss_zip_uri to $jboss_zip_path"
    $wc.DownloadFile($jboss_zip_uri, $jboss_zip_path)

    verbose "Unpacking into $target_dir_name"
    unzip $jboss_zip_path $target_dir_name

    if ($liverun) {
        $jboss_home = (get-childitem $target_dir_name | where-object {$_.Name -match "^jboss-"}).FullName

        verbose "JBOSS_HOME = $jboss_home"

	$env:JBOSS_HOME = $jboss_home
	[Environment]::SetEnvironmentVariable("JBOSS_HOME", 
                                              $jboss_home,
                                              "Machine")

        $jboss_conf = $jboss_home + "\bin\run.conf.bat"
        verbose "Enabling all interfaces"
        Add-Content $jboss_conf ""
        Add-Content $jboss_conf "rem Bind to all network interfaces"
        Add-Content $jboss_conf "set `"JAVA_OPTS=%JAVA_OPTS% -Djboss.bind.address=$bind_address`""
    }

    # move the port set from ports-default to ports-01
    debug "Replacing default port maps: $oldmarker -> $newmarker"
    # replace the binding set in the default server config
    if ($liverun) {
	$jboss_bindings_file = $jboss_home + "\server\default\conf\bindingservice.beans\META-INF\bindings-jboss-beans.xml"

        (get-content $jboss_bindings_file) | foreach-object {$_ -replace $oldmarker, $newmarker} | set-content $jboss_bindings_file
    }

    # Add a firewall rule to allow JBoss access
    debug "adding Jboss firewall rule"
    $fw = new-object -comObject HNetCfg.FwPolicy2
    $fwrule = new-object -comObject HNetCfg.FwRule
    $fwrule.Name = "JBoss AS (Tcp-In)"
    $fwrule.Description = "JBoss Application Server Inbound Access"
    $fwrule.Protocol = 6 # TCP
    $fwrule.LocalPorts = "8109,8180,8543"
    $fwrule.Direction = 1 # Inbound
    $fwrule.Action = 1 # Allow
    if ($liverun) { $fw.Rules.Add($fwrule) }
    $fwrule.Enabled = $true

    # add JBOSS to the end of PATH
    debug "Adding $jboss_home\bin to Path" 
    if ($liverun) {
        $env:PATH += (";" + $jboss_home + "\bin")
        [Environment]::SetEnvironmentVariable("Path", $env:PATH, "Machine")
    }
}

function Check_JBoss {
    debug "Checking JBoss"

    # JBOSS_HOME is set

    # JBOSS_HOME exists

    # JBOSS_HOME/bin exists

    # Check that port set selection was successful

    # check that firewall rule has been added
}

function Enable_JBoss_SSL {
    param ($jboss_service = "default", 
           $key_pass="notsecure" ,
           $dname)

    $jboss_root = $env:JBOSS_HOME

    $jboss_conf_dir = $jboss_root + "\server\" + $jboss_service + "\conf\"
    $jboss_deploy_dir = $jboss_root + "\server\" + $jboss_service + "\deploy\"
    $jboss_server_xml = $jboss_deploy_dir + "jbossweb.sar\server.xml" 
    $jboss_server_xml_orig = $jboss_server_xml + ".orig"

    # Key Generation Variable
    $keytool = $env:JAVA_HOME + "\bin\keytool.exe"
    $key_type = "RSA"
    $key_alias = "tomcat"
    $key_store = "ssl.keystore"
    $key_file = $jboss_conf_dir + $key_store
    # Generate the key file

    # check that jboss_conf_dir exists

    $cmd = "$keytool -genkey -alias $key_alias -keyalg $key_type -keystore $key_file -keypass $key_pass -storepass $key_pass -dname '$dname'"
    debug "Executing: $cmd"
    & $keytool -genkey -alias $key_alias -keyalg $key_type -keystore $key_file -keypass $key_pass -storepass $key_pass -dname $dname

    copy $jboss_server_xml $jboss_server_xml_orig

    debug "reading $jboss_server_xml_orig"

    $fin = [System.IO.File]::OpenText($jboss_server_xml_orig)
    $begin = $false
    $end = $false

    $out = while ($fin.Peek() -ne -1) {
    	$line = $fin.ReadLine()

    	# find the beginning of the commented SSL section
    	if (-not $begin -and $line -match "<!-- SSL/TLS Connector") {
      	    $begin = $true
      	    $line = $line + " -->"
    	} elseif ($begin -and -not $end) {
      	    if  ($line -match "-->$") {
                $end = $true
                $line = $line -replace "-->", "<!-- -->"
       	    } else {

	        # Replace the default protocol so SSL works
	    	$line = $line -replace 'protocol="HTTP/1.1"', 'protocol="org.apache.coyote.http11.Http11Protocol"'
                # Set the key store password
                $line = $line -replace 'keystorePass="[^"]+"', ('keystorePass="' + $key_pass + '"')

                # Locate the keystore file
	 	$line = $line -replace 'keystoreFile="[^"]+"', ('keystoreFile="${jboss.server.home.dir}/conf/' + $key_store + '"')
       	    }       
    	}
        $line
    }
    $fin.Close()
    debug "writing $jboss_server_xml"

    set-content ($jboss_server_xml + ".bin") $out
    get-content -Encoding Byte ($jboss_server_xml + ".bin") | where {$_ -ne 13} | set-content -Encoding Byte $jboss_server_xml
    remove-item ($jboss_server_xml + ".bin")

}

function Check_JBoss_SSL {
    debug "Checking JBoss SSL"

}

function Enable_JBoss_Service {
    param ($jboss_service_uri = $null)

    $jboss_root = $env:JBOSS_HOME
    $jboss_bin = $jboss_root + "\bin"

    if ($jboss_service_uri) {
        $jboss_service_zip = ($jboss_service_uri -split "/")[-1]
        $jboss_service_path = $download_root + $jboss_service_zip
        $jboss_conf = $jboss_bin + "\run.conf.bat"

        # install the JBOSS service
        debug "downloading jboss native service: $jboss_service_uri"
        debug "to $jboss_service_path"

        $wc.DownloadFile($jboss_service_uri, $jboss_service_path)

	# copy just the .exe files from bin
        if ($liverun) {
	    $sh = new-object -comObject shell.application
	    $bindir = $sh.NameSpace($jboss_root + "\bin")
	    $binzip = $sh.NameSpace($jboss_service_path + "\bin")
	    $bindir.CopyHere(($binzip.Items() | where-object {$_.Type -ne "File Folder"}), 4 + 16 + 512)	    
        }
    }

    debug "installing JBoss service"
    if ($liverun) { $cwd = pwd ; cd $jboss_bin ; .\service.bat install ; cd $cwd }

    debug "setting service to start automatically"
    if ($liverun) { 
       $jboss_service = Get-WmiObject Win32_Service | where {$_.Name -eq "JBAS50SVC"}
       $jboss_service.ChangeStartMode("Automatic")
    }

    debug "starting JBoss service"
    if ($liverun) { net start JBAS50SVC }
}

function Check_JBoss_Service {
    debug "Checking JBoss Service"

}

function Deploy_RHEVM_API {
    param($rhevm_api_war_uri, 
          $jboss_service = "default", 
          $rhevm_api_deploy_file = "rhevm-powershell-api.war")

    $rhevm_api_war_file = ($rhevm_api_war_uri -split "/")[-1]
    $rhevm_api_war_path = $download_root + $rhevm_api_war_file

    $jboss_deploy_root = $env:CATALINA_HOME + "\webapps\"

    $rhevm_api_deploy_path = $jboss_deploy_root + $rhevm_api_deploy_file

    debug "Downloading RHEVM-API .war file: $rhevm_api_war_uri"
    $wc.DownloadFile($rhevm_api_war_uri, $rhevm_api_war_path)
    
    debug "Copying $rhevm_api_war_path to $rhevm_api_deploy_path"
    if ($liverun) { copy $rhevm_api_war_path $rhevm_api_deploy_path }
}

function Check_RHEVM_API {
  debug "Checking RHEVM_API"

}

function Setup_Rhevm {

    debug "Setting up RHEVM"

    $parts = ("iis", "dotnet", "rhevm", "jre", "jdk", "tomcat", "jboss", "ssl", "service", "api")

    # Add feature IIS
    Install_IIS
    Check_IIS
    Install_RHEVM $rhevm_installer_uri $rhevm_config_uri
    Check_RHEVM

#    Install_JRE $jre_installer_uri
    Install_JDK $jdk_installer_uri
    Check_JDK

    $tomcat_root = Install_Tomcat $tomcat_uri
    Enable_Tomcat_SSL $tomcat_root -dname $tomcat_dname
    Enable_Tomcat_Service $tomcat_root

#    Install_JBoss $jboss_zip_uri
#    Check_JBoss
#    Enable_JBoss_SSL -DName $jboss_dname
#    Check_JBoss_SSL
#    Enable_JBoss_Service $jboss_service_uri
#    #Enable_JBoss_Service
#    Check_JBoss_Service


    Deploy_RHEVM_API $rhevm_api_war_uri
    Check_RHEVM_API

    debug "RHEVM Setup Complete"
}

Setup_Rhevm
exit
