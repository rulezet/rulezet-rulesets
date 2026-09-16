rule Webshell_JspSpyJDK5_RID2E1D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 11:00:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "14e9688c86b454ed48171a9d4f48ace8"
      hash2 = "341298482cf90febebb8616426080d1d"
      hash3 = "88fc87e7c58249a398efd5ceae636073"
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");" fullword
      $s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword
   condition: 
      1 of them
}