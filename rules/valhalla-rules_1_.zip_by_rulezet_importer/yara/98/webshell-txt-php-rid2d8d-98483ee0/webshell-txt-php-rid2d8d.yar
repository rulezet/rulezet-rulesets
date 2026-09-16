rule Webshell_Txt_php_RID2D8D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file php.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 10:36:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
      $s2 = "gzuncompress($_SESSION['api']),null);" ascii
      $s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
      $s4 = "if(empty($_SESSION['api']))" fullword ascii
   condition: 
      filesize < 1KB and all of them
}