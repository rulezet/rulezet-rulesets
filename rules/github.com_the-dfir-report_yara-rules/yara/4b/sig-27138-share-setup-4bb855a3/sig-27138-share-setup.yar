rule sig_27138_share__SETUP {
   meta:
      description = "27138 - file SETUP.bat"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "7673a949181e33ff8ed77d992a2826c25b8da333f9e03213ae3a72bb4e9a705d"
   strings:
      $s1 = "net share share$=%cd% /GRANT:Everyone,READ /Y" fullword ascii
      $s2 = "if %errorLevel% == 0 (" fullword ascii
      $s3 = "echo ERROR! Please run this file as Administrator!" fullword ascii
      $s4 = "net session >nul 2>&1" fullword ascii
      $s5 = "echo Administrative permissions required." fullword ascii
      $s6 = "echo Success : Administrative permissions confirmed." fullword ascii
      $s7 = ") else (" fullword ascii
      $s8 = "cd %~dp0" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      all of them
}