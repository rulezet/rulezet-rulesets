rule Webshell_2_520_job_ma1_ma4_2_RID30B8 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 12:51:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "56c005690da2558690c4aa305a31ad37"
      hash3 = "532b93e02cddfbb548ce5938fe2f5559"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" " 
      $s9 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getR" 
   condition: 
      all of them
}