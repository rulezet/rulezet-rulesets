rule Webshell_jsp_k81_RID2D26 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Web Shell - file k81.jsp"
      author = "Florian Roth"
      reference = "-"
      date = "2014-01-28 10:19:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
      $s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword
   condition: 
      1 of them
}