rule WindosShell_s1_RID2C80 : DEMO EXE FILE MAL SCRIPT {
   meta:
      description = "Detects simple Windows shell - file s1.exe"
      author = "Florian Roth"
      reference = "https://github.com/odzhan/shells/"
      date = "2016-03-26 09:51:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[ executing cmd.exe" fullword ascii
      $s2 = "[ simple remote shell for windows v1" fullword ascii
      $s3 = "-p <number>  Port number to use (default is 443)" fullword ascii
      $s4 = "usage: s1 <address> [options]" fullword ascii
      $s5 = "[ waiting for connections on %s" fullword ascii
      $s6 = "-l           Listen for incoming connections" fullword ascii
      $s7 = "[ connection from %s" fullword ascii
      $s8 = "[ %c%c requires parameter" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}