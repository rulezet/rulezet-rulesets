rule APT_WEBSHELL_HAFNIUM_SecChecker_Mar21_1_RID33B3 : APT DEMO G0125 T1505_003 WEBSHELL {
   meta:
      description = "Detects HAFNIUM SecChecker webshell"
      author = "Florian Roth"
      reference = "https://twitter.com/markus_neis/status/1367794681237667840"
      date = "2021-03-05 14:59:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"
      tags = "APT, DEMO, G0125, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "<%if(System.IO.File.Exists(\"c:\\\\program files (x86)\\\\fireeye\\\\xagt.exe" ascii
      $x2 = "\\csfalconservice.exe\")){Response.Write( \"3\");}%></head>" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 1KB and 1 of them or 2 of them
}