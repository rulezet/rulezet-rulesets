rule Webshell_lurm_safemod_on_cgi_RID3272 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file lurm_safemod_on.cgi.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 14:05:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Network security team :: CGI Shell" fullword
      $s1 = "#########################<<KONEC>>#####################################" fullword
      $s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword
   condition: 
      1 of them
}