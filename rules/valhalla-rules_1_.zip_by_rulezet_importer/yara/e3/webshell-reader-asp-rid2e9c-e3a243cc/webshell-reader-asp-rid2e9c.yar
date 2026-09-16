rule Webshell_Reader_asp_RID2E9C : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file Reader.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:21:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Mehdi & HolyDemon" 
      $s2 = "www.infilak." 
      $s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%" 
   condition: 
      2 of them
}