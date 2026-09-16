rule Webshell_Shell_Asp_RID2E21 : CHINA DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set Webshells - file Asp.html"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:01:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
      $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
      $s3 = "function Command(cmd, str){" fullword ascii
   condition: 
      filesize < 100KB and all of them
}