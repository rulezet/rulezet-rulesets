rule Webshell_JSP_icesword_RID2F52 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:52:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
      hash3 = "56c005690da2558690c4aa305a31ad37"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>" fullword
      $s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />" fullword
      $s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />" fullword
   condition: 
      2 of them
}