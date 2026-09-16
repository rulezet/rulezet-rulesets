rule WebShell_Gamma_Web_Shell_RID303D : DEMO SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "PHP Webshells Github Archive - file Gamma Web Shell.php"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:31:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];" fullword
      $s8 = "### Gamma Group <http://www.gammacenter.com>" fullword
      $s15 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword
      $s20 = "my $command = $self->query('command');" fullword
   condition: 
      2 of them
}