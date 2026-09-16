rule Webshell_asp_up_RID2D2E : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file up.asp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:20:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio" 
      $s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword
   condition: 
      1 of them
}