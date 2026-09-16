rule Impacket_Tools_lookupsid_RID30E8 : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:59:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "47756725d7a752d3d3cfccfb02e7df4fa0769b72e008ae5c85c018be4cf35cc1"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "slookupsid" fullword ascii
      $s2 = "impacket.dcerpc" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 15000KB and all of them )
}