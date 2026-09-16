rule DarkSecurityTeam_Webshell_RID3107 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Dark Security Team Webshell"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-02 13:05:01"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii
   condition: 
      1 of them
}