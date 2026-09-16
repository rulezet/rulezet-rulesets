rule APT30_Generic_8_RID2C0C : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample - from files 7c307ca84f922674049c0c43ca09bec1, b8617302180d331e197cc0433fc5023d, e6289e7f9f26be692cbe6f335a706014"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:32:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a9a50673ac000a313f3ddba55d63d9773b9f4143"
      hash2 = "ac96d7f5957aef09bd983465c497de24c6d17a92"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Windows NT4.0" fullword
      $s1 = "Windows NT3.51" fullword
      $s2 = "%d;%d;%d;%ld;%ld;%ld;" fullword
      $s3 = "%s %d.%d Build%d %s" fullword
      $s4 = "MSAFD Tcpip [TCP/IP]" fullword
      $s5 = "SQSRSS" fullword
      $s8 = "WM_COMP" fullword
      $s9 = "WM_MBU" fullword
      $s11 = "WM_GRID" fullword
      $s12 = "WM_RBU" fullword
   condition: 
      filesize < 250KB and uint16 ( 0 ) == 0x5A4D and all of them
}