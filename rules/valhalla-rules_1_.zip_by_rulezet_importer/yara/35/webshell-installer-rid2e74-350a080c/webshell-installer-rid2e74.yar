rule Webshell_installer_RID2E74 : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file installer.cmd"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 11:15:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Restore Old Vanquish" 
      $s4 = "ReInstall Vanquish" 
   condition: 
      all of them
}