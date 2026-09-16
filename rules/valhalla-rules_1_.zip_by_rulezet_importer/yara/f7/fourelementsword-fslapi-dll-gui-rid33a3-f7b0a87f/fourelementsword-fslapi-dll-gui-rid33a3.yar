rule FourElementSword_fslapi_dll_gui_RID33A3 : DEMO EXE FILE MAL {
   meta:
      description = "Detects FourElementSword Malware"
      author = "Florian Roth"
      reference = "not set"
      date = "2016-03-26 14:56:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "fslapi.dll.gui" fullword wide
      $s2 = "ImmGetDefaultIMEWnd" fullword ascii
      $s3 = "RichOX" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 12KB and all of them )
}