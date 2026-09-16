rule Webshell_Txt_aspxtag_RID2F3D : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Chinese Hacktool Set - Webshells - file aspxtag.txt"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-14 11:48:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "String wGetUrl=Request.QueryString[" fullword ascii
      $s2 = "sw.Write(wget);" fullword ascii
      $s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii
   condition: 
      filesize < 2KB and all of them
}