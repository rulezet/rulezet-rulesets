rule SUSP_ESXiArgs_Endpoint_Conf_Aug23_RID3307 : DEMO SUSP {
   meta:
      description = "Detects indicators found in endpoint.conf files as modified by actors in the ESXiArgs campaign"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-47"
      date = "2023-08-04 14:30:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "/client/clients.xml" ascii
      $a2 = "/var/run/vmware/proxy-sdk-tunnel" ascii fullword
      $a3 = "redirect" ascii fullword
      $a4 = "allow" ascii fullword
      $s1 = " local 8008 allow allow" 
   condition: 
      filesize < 2KB and all of them
}