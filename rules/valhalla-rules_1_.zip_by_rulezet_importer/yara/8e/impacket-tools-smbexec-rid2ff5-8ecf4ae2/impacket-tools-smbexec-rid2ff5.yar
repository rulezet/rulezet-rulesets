rule Impacket_Tools_smbexec_RID2FF5 : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:19:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7d715217e23a471d42d95c624179fe7de085af5670171d212b7b798ed9bf07c2"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "logging.config(" ascii
      $s2 = "ssmbexec" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 17000KB and all of them )
}