rule CN_Honker_ms11080_withcmd_RID2FF0 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ms11080_withcmd.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:18:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
      $s3 = "[>] create pipe error" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 340KB and all of them
}