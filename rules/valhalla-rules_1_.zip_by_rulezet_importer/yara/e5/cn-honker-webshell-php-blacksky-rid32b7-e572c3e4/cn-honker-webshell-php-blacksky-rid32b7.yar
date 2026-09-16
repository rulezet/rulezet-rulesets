rule CN_Honker_Webshell_PHP_BlackSky_RID32B7 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php6.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:17:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "eval(gzinflate(base64_decode('" ascii
      $s1 = "B1ac7Sky-->" fullword ascii
   condition: 
      filesize < 641KB and all of them
}