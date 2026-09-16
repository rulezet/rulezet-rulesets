rule SUSP_TINY_PE_RID2AF3 : DEMO EXE FILE SUSP {
   meta:
      description = "Detects Tiny PE file"
      author = "Florian Roth"
      reference = "https://webserver2.tecgraf.puc-rio.br/~ismael/Cursos/YC++/apostilas/win32_xcoff_pe/tyne-example/Tiny%20PE.htm"
      date = "2019-10-23 09:36:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $header = { 4D 5A 00 00 50 45 00 00 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and uint16 ( 4 ) == 0x4550 and filesize <= 20KB and $header at 0
}