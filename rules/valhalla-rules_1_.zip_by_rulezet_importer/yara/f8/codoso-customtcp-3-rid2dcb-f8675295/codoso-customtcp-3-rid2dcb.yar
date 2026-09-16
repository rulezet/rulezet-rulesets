rule Codoso_CustomTCP_3_RID2DCB : DEMO EXE G0073 MAL {
   meta:
      description = "Detects Codoso APT CustomTCP Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 10:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, G0073, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "DnsApi.dll" fullword ascii
      $s2 = "softWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s" ascii
      $s3 = "CONNECT %s:%d hTTP/1.1" ascii
      $s4 = "CONNECT %s:%d HTTp/1.1" ascii
      $s5 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0;)" ascii
      $s6 = "iphlpapi.dll" ascii
      $s7 = "%systemroot%\\Web\\" ascii
      $s8 = "Proxy-Authorization: Negotiate %s" ascii
      $s9 = "CLSID\\{%s}\\InprocServer32" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 5 of them ) or 7 of them
}