rule NetBIOS_Name_Scanner {
   meta:
      description = "Auto-generated rule on file NetBIOS Name Scanner.exe"
      author = "yarGen Yara Rule Generator by Florian Roth"
      hash = "888ba1d391e14c0a9c829f5a1964ca2c"
      id = "03716e00-a969-5ab5-9be7-e8fc4272e40f"
   strings:
      $s0 = "IconEx"
      $s2 = "soft Visual Stu"
      $s4 = "NBTScanner!y&"
   condition:
      all of them
}