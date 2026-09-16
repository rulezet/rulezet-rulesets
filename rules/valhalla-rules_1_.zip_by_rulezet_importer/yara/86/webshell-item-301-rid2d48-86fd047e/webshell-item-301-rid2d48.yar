rule Webshell_item_301_RID2D48 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file item-301.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:25:11"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
      $s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
      $s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
      $s4 = "$sURL = $aArg[0];" fullword ascii
   condition: 
      filesize < 3KB and 3 of them
}