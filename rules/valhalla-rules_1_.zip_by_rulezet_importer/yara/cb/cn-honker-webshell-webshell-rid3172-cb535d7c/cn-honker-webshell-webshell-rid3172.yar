rule CN_Honker_Webshell_WebShell_RID3172 : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file WebShell.cgi"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:22:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$login = crypt($WebShell::Configuration::password, $salt);" fullword ascii
      $s2 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword ascii
      $s3 = "warn \"command: '$command'\\n\";" fullword ascii
   condition: 
      filesize < 30KB and 2 of them
}