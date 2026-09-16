import "pe"
rule APT_DarkHydrus_Jul18_3_RID2EDB : APT DEMO EXE FILE G0079 MIDDLE_EAST {
   meta:
      description = "Detects strings found in malware samples in APT report in DarkHydrus"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
      date = "2018-07-28 11:32:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c8b3d4b6acce6b6655e17255ef7a214651b7fc4e43f9964df24556343393a1a3"
      tags = "APT, DEMO, EXE, FILE, G0079, MIDDLE_EAST"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "Ws2_32.dll" fullword ascii
      $s3 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and ( pe.imphash ( ) == "478eacfbe2b201dabe63be53f34148a5" or all of them )
}