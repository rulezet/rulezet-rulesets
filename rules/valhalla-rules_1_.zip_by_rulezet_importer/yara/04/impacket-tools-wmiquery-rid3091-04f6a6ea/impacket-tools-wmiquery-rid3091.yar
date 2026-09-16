rule Impacket_Tools_wmiquery_RID3091 : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:45:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "202a1d149be35d96e491b0b65516f631f3486215f78526160cf262d8ae179094"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "swmiquery" fullword ascii
      $s2 = "\\yzHPlU=QA" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 17000KB and all of them )
}