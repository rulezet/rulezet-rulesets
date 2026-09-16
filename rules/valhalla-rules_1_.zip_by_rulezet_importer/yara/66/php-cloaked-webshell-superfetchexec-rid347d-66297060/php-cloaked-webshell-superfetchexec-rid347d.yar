rule PHP_Cloaked_Webshell_SuperFetchExec_RID347D : ANOMALY DEMO T1036 T1505_003 WEBSHELL {
   meta:
      description = "Looks like a webshell cloaked as GIF - https://pastebin.com/1XE208s6"
      author = "Florian Roth"
      reference = "https://pastebin.com/1XE208s6"
      date = "2014-04-05 15:32:41"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "ANOMALY, DEMO, T1036, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);" 
   condition: 
      $s0
}