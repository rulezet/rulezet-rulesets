rule Webshell_2_520_job_JspWebshell_1_2_ma1_ma4_2_RID369B : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, JspWebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 17:03:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9abd397c6498c41967b4dd327cf8b55a"
      hash2 = "56c005690da2558690c4aa305a31ad37"
      hash3 = "70a0ee2624e5bbe5525ccadc467519f6"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {" fullword
      $s6 = "password = (String)session.getAttribute(\"password\");" fullword
      $s7 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231" 
   condition: 
      2 of them
}