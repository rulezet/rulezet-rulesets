rule Webshell_CN_Tools_item_RID2FB5 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file item.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 12:08:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
      $s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
      $s3 = "$sWget=\"index.asp\";" fullword ascii
      $s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
   condition: 
      filesize < 4KB and all of them
}