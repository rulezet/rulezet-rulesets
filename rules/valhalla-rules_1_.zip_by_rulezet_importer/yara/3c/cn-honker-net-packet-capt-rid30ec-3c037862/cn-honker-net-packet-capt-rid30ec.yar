rule CN_Honker_net_packet_capt_RID30EC : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file net_packet_capt.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:00:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "(*.sfd)" fullword ascii
      $s2 = "GetLaBA" fullword ascii
      $s3 = "GAIsProcessorFeature" fullword ascii
      $s4 = "- Gablto " ascii
      $s5 = "PaneWyedit" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and all of them
}