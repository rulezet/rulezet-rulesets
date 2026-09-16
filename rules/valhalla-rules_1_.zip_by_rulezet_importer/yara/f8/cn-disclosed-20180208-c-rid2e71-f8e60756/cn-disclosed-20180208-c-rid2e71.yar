rule CN_disclosed_20180208_c_RID2E71 : CHINA DEMO EXE FILE MAL T1047 T1053_005 {
   meta:
      description = "Detects malware from disclosed CN malware set"
      author = "Florian Roth"
      reference = "https://twitter.com/cyberintproject/status/961714165550342146"
      date = "2018-02-08 11:14:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "17475d25d40c877284e73890a9dd55fccedc6a5a071c351a8c342c8ef7f9cea7"
      tags = "CHINA, DEMO, EXE, FILE, MAL, T1047, T1053_005"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide
      $x2 = "schtasks /create /sc minute /mo 1 /tn Server /tr " fullword wide
      $x3 = "www.upload.ee/image/" wide
      $s1 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide
      $s2 = "/Server.exe" fullword wide
      $s3 = "Executed As " fullword wide
      $s4 = "WmiPrvSE.exe" fullword wide
      $s5 = "Stub.exe" fullword ascii
      $s6 = "Download ERROR" fullword wide
      $s7 = "shutdown -r -t 00" fullword wide
      $s8 = "Select * From AntiVirusProduct" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) or 4 of them )
}