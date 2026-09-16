rule CN_Honker_Codeeer_Explorer_RID312E : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Codeeer Explorer.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:11:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "Codeeer Explorer.exe" fullword wide
      $s12 = "webBrowser1_ProgressChanged" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 470KB and all of them
}