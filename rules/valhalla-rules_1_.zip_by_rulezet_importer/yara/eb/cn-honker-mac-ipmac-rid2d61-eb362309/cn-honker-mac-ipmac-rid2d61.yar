rule CN_Honker_MAC_IPMAC_RID2D61 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file IPMAC.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:29:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Http://Www.YrYz.Net" fullword wide
      $s2 = "IpMac.txt" fullword ascii
      $s3 = "192.168.0.1" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 267KB and all of them
}