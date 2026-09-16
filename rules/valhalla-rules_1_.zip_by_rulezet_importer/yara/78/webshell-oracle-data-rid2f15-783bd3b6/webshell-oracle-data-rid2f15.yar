rule Webshell_oracle_data_RID2F15 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - file oracle_data.php"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 11:42:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
      $s1 = "if(isset($_REQUEST['id']))" fullword ascii
      $s2 = "$id=$_REQUEST['id'];" fullword ascii
   condition: 
      all of them
}