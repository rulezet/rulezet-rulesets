rule WiltedTulip_SilverlightMSI_RID315D : APT DEMO SCRIPT T1059_001 {
   meta:
      description = "Detects powershell tool call Get_AD_Users_Logon_History used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 13:19:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c75906dbc3078ff81092f6a799c31afc79b1dece29db696b2ecf27951a86a1b2"
      tags = "APT, DEMO, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ".\\Get_AD_Users_Logon_History.ps1 -MaxEvent" fullword ascii
      $x2 = "if ((Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly -ErrorAction \"SilentlyContinue\").Type -eq \"PTR\")" fullword ascii
      $x3 = "$Client_Name = (Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly).NameHost  " fullword ascii
      $x4 = "########## Find the Computer account in AD and if not found, throw an exception ###########" fullword ascii
   condition: 
      ( filesize < 20KB and 1 of them )
}