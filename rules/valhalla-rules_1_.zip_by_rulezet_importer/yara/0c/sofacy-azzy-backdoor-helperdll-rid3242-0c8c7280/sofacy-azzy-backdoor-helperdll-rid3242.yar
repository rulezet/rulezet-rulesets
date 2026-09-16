rule Sofacy_AZZY_Backdoor_HelperDLL_RID3242 : APT DEMO EXE FILE G0007 RUSSIA {
   meta:
      description = "Dropped C&C helper DLL for AZZY 4.3"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
      date = "2015-12-04 13:57:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, G0007, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "snd.dll" fullword ascii
      $s1 = "InternetExchange" fullword ascii
      $s2 = "SendData" 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}