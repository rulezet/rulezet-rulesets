rule Webshell_WebShell_cgi_RID2F4E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file WebShell.cgi.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:51:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "WebShell.cgi" 
      $s2 = "<td><code class=\"entry-[% if entry.all_rights %]mine[% else" 
   condition: 
      all of them
}