rule Webshell_warfiles_cmd_RID2F96 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file cmd.jsp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 12:03:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii
      $s2 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii
      $s3 = "<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">" fullword ascii
      $s4 = "String disr = dis.readLine();" fullword ascii
   condition: 
      filesize < 2KB and all of them
}