rule EquationGroup_Toolset_Apr17_wmi_Implant_RID3677 : APT DEMO EXE FILE T1047 T1057 T1546_003 {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:57:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "de08d6c382faaae2b4b41b448b26d82d04a8f25375c712c12013cb0fac3bc704"
      tags = "APT, DEMO, EXE, FILE, T1047, T1057, T1546_003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "SELECT ProcessId,Description,ExecutablePath FROM Win32_Process" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and all of them )
}