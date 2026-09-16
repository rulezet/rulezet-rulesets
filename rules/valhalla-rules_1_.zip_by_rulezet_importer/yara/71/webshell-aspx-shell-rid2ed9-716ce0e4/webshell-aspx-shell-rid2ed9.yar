rule Webshell_aspx_shell_RID2ED9 : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file shell.aspx"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 11:32:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii
      $s2 = "remoteIp = Request.UserHostAddress;" fullword ascii
      $s3 = "<form method=\"post\" name=\"shell\">" fullword ascii
      $s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii
   condition: 
      filesize < 20KB and all of them
}