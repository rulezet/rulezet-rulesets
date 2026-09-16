rule VBS_WMIExec_Tool_Apr17_1_RID2F44 : APT DEMO SCRIPT {
   meta:
      description = "Tools related to Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 11:49:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "21bc328ed8ae81151e7537c27c0d6df6d47ba8909aebd61333e32155d01f3b11"
      tags = "APT, DEMO, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "strNetUse = \"cmd.exe /c net use \\\\\" & host" fullword ascii
      $x2 = "localcmd = \"cmd.exe /c \" & command " ascii
      $x3 = "& \" > \" & TempFile & \" 2>&1\"  '2>&1 err" fullword ascii
      $x4 = "strExec = \"cmd.exe /c \" & cmd & \" >> \" & resultfile & \" 2>&1\"  '2>&1 err" fullword ascii
      $x5 = "TempFile = objShell.ExpandEnvironmentStrings(\"%TEMP%\") & \"\\wmi.dll\"" fullword ascii
      $a1 = "WMIEXEC ERROR: Command -> " ascii
      $a2 = "WMIEXEC : Command result will output to" fullword ascii
      $a3 = "WMIEXEC : Target ->" fullword ascii
      $a4 = "WMIEXEC : Login -> OK" fullword ascii
      $a5 = "WMIEXEC : Process created. PID:" fullword ascii
   condition: 
      ( filesize < 40KB and 1 of them ) or 3 of them
}