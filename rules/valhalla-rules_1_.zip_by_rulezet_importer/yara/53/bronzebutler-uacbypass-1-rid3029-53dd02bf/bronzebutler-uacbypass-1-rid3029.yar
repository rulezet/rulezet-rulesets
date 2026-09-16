rule BronzeButler_UACBypass_1_RID3029 : APT CHINA DEMO EXE FILE G0060 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      author = "Florian Roth"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14 12:28:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fe06b99a0287e2b2d9f7faffbda3a4b328ecc05eab56a3e730cfc99de803b192"
      tags = "APT, CHINA, DEMO, EXE, FILE, G0060"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\BypassUacDll.pdb" ascii
      $x2 = "%programfiles%internet exploreriexplore.exe" fullword wide
      $x3 = "Elevation:Administrator!new:{3ad055" fullword wide
      $x4 = "BypassUac.pdb" fullword ascii
      $x5 = "[bypassUAC] started X64" fullword wide
      $x6 = "[bypassUAC] started X86" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 1 of them )
}