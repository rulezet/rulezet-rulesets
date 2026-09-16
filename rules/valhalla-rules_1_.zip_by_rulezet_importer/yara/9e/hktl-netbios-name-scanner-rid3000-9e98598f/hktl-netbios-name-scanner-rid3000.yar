rule HKTL_NetBIOS_Name_Scanner_RID3000 : DEMO HKTL {
   meta:
      description = "Semiautomatically generated YARA rule on file NetBIOS Name Scanner.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 12:21:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "IconEx" 
      $s2 = "soft Visual Stu" 
      $s4 = "NBTScanner!y&" 
   condition: 
      all of them
}