rule Equation_Kaspersky_GreyFishInstaller_RID35A1 : APT DEMO G0020 {
   meta:
      description = "Equation Group Malware - Grey Fish"
      author = "Florian Roth"
      reference = "https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/"
      date = "2015-02-16 16:21:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "DOGROUND.exe" fullword wide
      $s1 = "Windows Configuration Services" fullword wide
      $s2 = "GetMappedFilenameW" fullword ascii
   condition: 
      all of them
}