rule Impacket_Tools_Generic_1_RID305B : DEMO EXE FILE GEN HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:36:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4f7fad0676d3c3d2d89e8d4e74b6ec40af731b1ddf5499a0b81fc3b1cd797ee3"
      hash2 = "d256d1e05695d62a86d9e76830fcbb856ba7bd578165a561edd43b9f7fdb18a3"
      hash3 = "2d8d500bcb3ffd22ddd8bd68b5b2ce935c958304f03729442a20a28b2c0328c1"
      tags = "DEMO, EXE, FILE, GEN, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "bpywintypes27.dll" fullword ascii
      $s2 = "hZFtPC" fullword ascii
      $s3 = "impacket" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 21000KB and all of ( $s* ) ) or ( all of them )
}