rule CrunchRAT_RID2A5B : DEMO EXE FILE MAL {
   meta:
      description = "Detects CrunchRAT_RID2A5B - file CrunchRAT_RID2A5B.exe"
      author = "Florian Roth"
      reference = "https://github.com/t3ntman/CrunchRAT_RID2A5B"
      date = "2017-11-03 05:23:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "58a07e96497745b6fd5075d569f17b0254c3e50b0234744e0487f7c5dddf7161"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "----CrunchRAT_RID2A5B" fullword wide
      $x2 = "\\Debug\\CrunchRAT_RID2A5B" ascii
      $x3 = "\\Release\\CrunchRAT_RID2A5B" ascii
      $s1 = "runCommand" fullword ascii
      $s2 = "<action>download<action>" fullword wide
      $s3 = "Content-Disposition: form-data; name=action" fullword wide
      $s4 = "<action>upload<action>" fullword wide
      $s5 = "/update.php" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and ( 1 of ( $x* ) and 3 of them )
}