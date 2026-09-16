rule Impacket_Tools_goldenPac_RID309B : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:47:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4f7fad0676d3c3d2d89e8d4e74b6ec40af731b1ddf5499a0b81fc3b1cd797ee3"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "impacket.examples.serviceinstall(" ascii
      $s2 = "bgoldenPac.exe" fullword ascii
      $s3 = "json.scanner(" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 17000KB and all of them )
}