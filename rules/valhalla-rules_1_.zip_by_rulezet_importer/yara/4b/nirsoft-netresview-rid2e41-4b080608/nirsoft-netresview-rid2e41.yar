rule Nirsoft_NetResView_RID2E41 : APT DEMO EXE FILE {
   meta:
      description = "Detects NirSoft NetResView - utility that displays the list of all network resources"
      author = "Florian Roth"
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/irongate-ics-malware/"
      date = "2016-06-04 11:06:41"
      score = 40
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "NetResView.exe" fullword wide
      $s2 = "2005 - 2013 Nir Sofer" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}