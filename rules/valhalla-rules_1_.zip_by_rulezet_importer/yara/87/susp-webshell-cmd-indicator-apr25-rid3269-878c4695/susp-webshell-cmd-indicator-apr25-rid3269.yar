rule SUSP_WEBSHELL_Cmd_Indicator_Apr25_RID3269 : DEMO SCRIPT SUSP T1505_003 WEBSHELL {
   meta:
      description = "Detects a pattern which is often related to web shell activity"
      author = "Florian Roth"
      reference = "https://regex101.com/r/N6oZ2h/2"
      date = "2025-04-25 14:04:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-05-07"
      tags = "DEMO, SCRIPT, SUSP, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $xr01 = /\.(asp|aspx|jsp|php)\?cmd=[a-z0-9%+\-\/\.]{3,20} HTTP\/1\.[01]["']? 200/ 
   condition: 
      1 of them
}