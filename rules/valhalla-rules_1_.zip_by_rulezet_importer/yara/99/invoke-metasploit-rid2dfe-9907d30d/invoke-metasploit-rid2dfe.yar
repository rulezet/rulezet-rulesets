rule Invoke_Metasploit_RID2DFE : DEMO HKTL METASPLOIT T1105 {
   meta:
      description = "Detects Invoke-Metasploit Payload"
      author = "Florian Roth"
      reference = "https://github.com/jaredhaight/Invoke-MetasploitPayload/blob/master/Invoke-MetasploitPayload.ps1"
      date = "2017-09-23 10:55:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b36d3ca7073741c8a48c578edaa6d3b6a8c3c4413e961a83ad08ad128b843e0b"
      tags = "DEMO, HKTL, METASPLOIT, T1105"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[*] Looks like we're 64bit, using regular powershell.exe" ascii wide
      $s2 = "[*] Kicking off download cradle in a new process" 
      $s3 = "Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;Invoke-Expression $client.downloadstring('''+$url+''');'" 
   condition: 
      ( filesize < 20KB and 1 of them )
}