rule WindowsShell_Gen2_RID2D9F : DEMO EXE FILE MAL SCRIPT {
   meta:
      description = "Detects simple Windows shell - from files s3.exe, s4.exe"
      author = "Florian Roth"
      reference = "https://github.com/odzhan/shells/"
      date = "2016-03-26 10:39:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
      hash2 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
      tags = "DEMO, EXE, FILE, MAL, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmd                  - execute cmd.exe" fullword ascii
      $s2 = "get <remote> <local> - download file" fullword ascii
      $s3 = "REMOTE: CreateFile(\"%s\")" fullword ascii
      $s4 = "put <local> <remote> - upload file" fullword ascii
      $s5 = "term                 - terminate remote client" fullword ascii
      $s6 = "[ uploading \"%s\" to \"%s\"" fullword ascii
      $s7 = "[ error : received %i bytes" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}