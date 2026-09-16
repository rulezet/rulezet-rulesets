rule CN_Honker_CnCerT_CCdoor_CMD_2_RID3143 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file CnCerT.CCdoor.CMD.dll2"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:15:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "cmd.dll" fullword wide
      $s1 = "cmdpath" fullword ascii
      $s2 = "Get4Bytes" fullword ascii
      $s3 = "ExcuteCmd" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 22KB and all of them
}