rule Webshell_2_520_icesword_job_ma1_ma4_2_RID3477 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 15:31:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
      hash3 = "56c005690da2558690c4aa305a31ad37"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\"," 
      $s3 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ" 
      $s9 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor" 
   condition: 
      all of them
}