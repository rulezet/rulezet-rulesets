rule SUSP_ESXiArgs_Endpoint_Conf_Aug23 {
   meta:
      description = "Detects indicators found in endpoint.conf files as modified by actors in the ESXiArgs campaign"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-47"
      date = "2023-08-04"
      score = 75
      id = "3e0b5dbf-7c5b-5599-823a-ce35fbdbe64b"
   strings:
      $a1 = "/client/clients.xml" ascii
      $a2 = "/var/run/vmware/proxy-sdk-tunnel" ascii fullword
      $a3 = "redirect" ascii fullword
      $a4 = "allow" ascii fullword

      $s1 = " local 8008 allow allow"
   condition:
      filesize < 2KB and all of them
}