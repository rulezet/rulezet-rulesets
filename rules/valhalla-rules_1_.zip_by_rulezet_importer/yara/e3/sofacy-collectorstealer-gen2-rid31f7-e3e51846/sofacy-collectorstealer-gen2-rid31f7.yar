rule Sofacy_CollectorStealer_Gen2_RID31F7 : APT DEMO EXE FILE G0007 GEN RUSSIA {
   meta:
      description = "File collectors / USB stealers - Generic"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
      date = "2015-12-04 13:45:01"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, G0007, GEN, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "msdetltemp.dll" fullword ascii
      $s2 = "msdeltemp.dll" fullword wide
      $s3 = "Delete Temp Folder Service" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}