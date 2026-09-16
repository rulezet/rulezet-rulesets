rule Impacket_Tools_ifmap_RID2F1B : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 11:43:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "20a1f11788e6cc98a76dca2db4691963c054fc12a4d608ac41739b98f84b3613"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "bifmap.exe.manifest" fullword ascii
      $s2 = "impacket.dcerpc.v5.epm(" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 15000KB and all of them )
}