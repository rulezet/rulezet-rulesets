rule WindowsShell_s4_RID2CFA : DEMO EXE FILE MAL SCRIPT {
   meta:
      description = "Detects simple Windows shell - file s4.exe"
      author = "Florian Roth"
      reference = "https://github.com/odzhan/shells/"
      date = "2016-03-26 10:12:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd                  - execute cmd.exe" fullword ascii
      $s2 = "\\\\.\\pipe\\%08X" fullword ascii
      $s3 = "get <remote> <local> - download file" fullword ascii
      $s4 = "[ simple remote shell for windows v4" fullword ascii
      $s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
      $s6 = "[ downloading \"%s\" to \"%s\"" fullword ascii
      $s7 = "[ uploading \"%s\" to \"%s\"" fullword ascii
      $s8 = "-l           Listen for incoming connections" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}