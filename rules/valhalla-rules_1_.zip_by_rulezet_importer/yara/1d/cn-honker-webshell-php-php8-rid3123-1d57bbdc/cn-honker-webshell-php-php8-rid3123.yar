rule CN_Honker_Webshell_PHP_php8_RID3123 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file php8.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:09:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<a href=\"http://hi.baidu.com/ca3tie1/home\" target=\"_blank\">Ca3tie1's Blog</a" ascii
      $s1 = "function startfile($path = 'dodo.zip')" fullword ascii
      $s3 = "<form name=\"myform\" method=\"post\" action=\"\">" fullword ascii
      $s5 = "$_REQUEST[zipname] = \"dodozip.zip\"; " fullword ascii
   condition: 
      filesize < 25KB and 2 of them
}