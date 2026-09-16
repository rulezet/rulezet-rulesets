rule Webshell_asp_dns_RID2D8E : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Laudanum Injector Tools - file dns.asp"
      author = "Florian Roth"
      reference = "http://laudanum.inguardians.com/"
      date = "2015-06-22 10:36:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "command = \"nslookup -type=\" & qtype & \" \" & query " fullword ascii
      $s2 = "Set objCmd = objWShell.Exec(command)" fullword ascii
      $s3 = "Response.Write command & \"<br>\"" fullword ascii
      $s4 = "<form name=\"dns\" method=\"POST\">" fullword ascii
   condition: 
      filesize < 21KB and all of them
}