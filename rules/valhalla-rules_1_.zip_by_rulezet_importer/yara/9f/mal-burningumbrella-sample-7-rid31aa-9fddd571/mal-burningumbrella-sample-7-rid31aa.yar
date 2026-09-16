import "pe"
rule MAL_BurningUmbrella_Sample_7_RID31AA : APT DEMO EXE FILE MAL {
   meta:
      description = "Detects malware sample from Burning Umbrella report"
      author = "Florian Roth"
      reference = "https://401trg.pw/burning-umbrella/"
      date = "2018-05-04 13:32:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a4ce3a356d61fbbb067e1430b8ceedbe8965e0cfedd8fb43f1f719e2925b094a"
      hash2 = "a8bfc1e013f15bc395aa5c047f22ff2344c343c22d420804b6d2f0a67eb6db64"
      hash3 = "959612f2a9a8ce454c144d6aef10dd326b201336a85e69a604e6b3892892d7ed"
      tags = "APT, DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and pe.imphash ( ) == "f5b113d6708a3927b5cc48f2215fcaff"
}