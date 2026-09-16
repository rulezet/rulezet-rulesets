rule Impacket_Tools_wmiexec_RID3000 : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "19544863758341fe7276c59d85f4aa17094045621ca9c98f8a9e7307c290bad4"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "bwmiexec.exe.manifest" fullword ascii
      $s2 = "swmiexec" fullword ascii
      $s3 = "\\yzHPlU=QA" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 17000KB and 2 of them )
}