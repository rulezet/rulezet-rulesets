rule ms11080_withcmd_RID2C3A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file ms11080_withcmd_RID2C3A.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:40:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
      $s2 = "\\ms11080\\ms11080\\Debug\\ms11080.pdb" ascii
      $s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
      $s4 = "[>] create porcess error" fullword ascii
      $s5 = "[>] ms11-080 Exploit" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them
}