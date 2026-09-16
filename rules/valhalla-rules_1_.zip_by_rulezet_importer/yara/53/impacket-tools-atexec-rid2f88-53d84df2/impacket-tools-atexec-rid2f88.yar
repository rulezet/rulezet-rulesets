rule Impacket_Tools_atexec_RID2F88 : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:01:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "337bd5858aba0380e16ee9a9d8f0b3f5bfc10056ced4e75901207166689fbedc"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "batexec.exe.manifest" fullword ascii
      $s2 = "satexec" fullword ascii
      $s3 = "impacket.dcerpc" fullword ascii
      $s4 = "# CSZq" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 15000KB and 3 of them )
}