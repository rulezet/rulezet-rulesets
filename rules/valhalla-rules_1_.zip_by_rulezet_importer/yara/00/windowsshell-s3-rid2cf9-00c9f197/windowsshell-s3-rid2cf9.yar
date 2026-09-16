rule WindowsShell_s3_RID2CF9 : DEMO EXE FILE MAL SCRIPT {
   meta:
      description = "Detects simple Windows shell - file s3.exe"
      author = "Florian Roth"
      reference = "https://github.com/odzhan/shells/"
      date = "2016-03-26 10:12:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd                  - execute cmd.exe" fullword ascii
      $s2 = "\\\\.\\pipe\\%08X" fullword ascii
      $s3 = "get <remote> <local> - download file" fullword ascii
      $s4 = "[ simple remote shell for windows v3" fullword ascii
      $s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
      $s6 = "put <local> <remote> - upload file" fullword ascii
      $s7 = "term                 - terminate remote client" fullword ascii
      $s8 = "[ downloading \"%s\" to \"%s\"" fullword ascii
      $s9 = "-l           Listen for incoming connections" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}