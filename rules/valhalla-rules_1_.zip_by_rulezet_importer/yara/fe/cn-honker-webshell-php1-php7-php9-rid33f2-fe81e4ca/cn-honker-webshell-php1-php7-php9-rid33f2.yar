rule CN_Honker_Webshell__php1_php7_php9_RID33F2 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - from files php1.txt, php7.txt, php9.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:09:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "05a3f93dbb6c3705fd5151b6ffb64b53bc555575"
      hash2 = "cd3962b1dba9f1b389212e38857568b69ca76725"
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<a href=\"?s=h&o=wscript\">[WScript.shell]</a> " fullword ascii
      $s2 = "document.getElementById('cmd').value = Str[i];" fullword ascii
      $s3 = "Str[7] = \"copy c:\\\\\\\\1.php d:\\\\\\\\2.php\";" fullword ascii
   condition: 
      filesize < 300KB and all of them
}