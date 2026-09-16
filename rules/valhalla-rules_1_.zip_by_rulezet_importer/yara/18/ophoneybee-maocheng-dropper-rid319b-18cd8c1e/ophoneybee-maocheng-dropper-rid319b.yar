rule OpHoneybee_MaoCheng_Dropper_RID319B : APT C0006 DEMO EXE FILE G0072 T1569_002 {
   meta:
      description = "Detects MaoCheng dropper from Operation Honeybee"
      author = "Florian Roth"
      reference = "https://www.mcafee.com:443/blogs/"
      date = "2018-03-03 13:29:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "35904f482d37f5ce6034d6042bae207418e450f4"
      tags = "APT, C0006, DEMO, EXE, FILE, G0072, T1569_002"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\MaoCheng\\Release\\" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 1 of them
}