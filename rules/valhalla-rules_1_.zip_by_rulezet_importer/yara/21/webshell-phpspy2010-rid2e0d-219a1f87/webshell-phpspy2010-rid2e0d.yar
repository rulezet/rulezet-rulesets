rule Webshell_phpspy2010_RID2E0D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file phpspy2010.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:58:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "eval(gzinflate(base64_decode(" 
      $s5 = "//angel" fullword
      $s8 = "$admin['cookiedomain'] = '';" fullword
   condition: 
      all of them
}