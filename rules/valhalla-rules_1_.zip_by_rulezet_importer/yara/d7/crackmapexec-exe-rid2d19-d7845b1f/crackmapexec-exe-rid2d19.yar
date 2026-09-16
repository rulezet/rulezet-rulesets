rule Crackmapexec_EXE_RID2D19 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects CrackMapExec hack tool"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-04-06 10:17:21"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "371f104b7876b9080c519510879235f36edb6668097de475949b84ab72ee9a9a"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "core.scripts.secretsdump(" ascii
      $s2 = "core.scripts.samrdump(" ascii
      $s3 = "core.uacdump(" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 10000KB and 2 of them
}