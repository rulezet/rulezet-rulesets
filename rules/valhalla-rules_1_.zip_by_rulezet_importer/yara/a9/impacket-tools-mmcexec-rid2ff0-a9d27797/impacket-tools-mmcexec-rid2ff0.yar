rule Impacket_Tools_mmcexec_RID2FF0 : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:18:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "263a1655a94b7920531e123a8c9737428f2988bf58156c62408e192d4b2a63fc"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "smmcexec" fullword ascii
      $s2 = "\\yzHPlU=QA" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 16000KB and all of them )
}