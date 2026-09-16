rule S_MultiFunction_Scanners_s_RID3182 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file s.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:25:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "C:\\WINDOWS\\temp\\pojie.exe /l=" fullword ascii
      $s1 = "C:\\WINDOWS\\temp\\s.exe" fullword ascii
      $s2 = "C:\\WINDOWS\\temp\\s.exe tcp " fullword ascii
      $s3 = "explorer.exe http://www.hackdos.com" fullword ascii
      $s4 = "C:\\WINDOWS\\temp\\pojie.exe" fullword ascii
      $s5 = "Failed to read file or invalid data in file!" fullword ascii
      $s6 = "www.hackdos.com" fullword ascii
      $s7 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
      $s11 = "The interface of kernel library is invalid!" fullword ascii
      $s12 = "eventvwr" fullword ascii
      $s13 = "Failed to decompress data!" fullword ascii
      $s14 = "NOTEPAD.EXE result.txt" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 8000KB and 4 of them
}