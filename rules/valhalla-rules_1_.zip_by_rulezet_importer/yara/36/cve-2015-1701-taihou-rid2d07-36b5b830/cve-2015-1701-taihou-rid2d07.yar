rule CVE_2015_1701_Taihou_RID2D07 : CVE_2015_1701 DEMO EXE EXPLOIT FILE T1068 {
   meta:
      description = "CVE-2015-1701 compiled exploit code"
      author = "Florian Roth"
      reference = "https://seclist.us/executable-payload-exploits-local-privilege-escalation-cve-2015-1701-to-steal-system-token.html"
      date = "2015-05-13 10:14:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "90d17ebd75ce7ff4f15b2df951572653efe2ea17"
      hash2 = "acf181d6c2c43356e92d4ee7592700fa01e30ffb"
      hash3 = "b8aabe12502f7d55ae332905acee80a10e3bc399"
      tags = "CVE_2015_1701, DEMO, EXE, EXPLOIT, FILE, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "VirtualProtect" fullword
      $s4 = "RegisterClass" 
      $s5 = "LoadIcon" 
      $s6 = "PsLookupProcessByProcessId" fullword ascii
      $s7 = "LoadLibraryExA" fullword ascii
      $s8 = "gSharedInfo" fullword
      $w1 = "user32.dll" wide
      $w2 = "ntdll" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 160KB and all of ( $s* ) and 1 of ( $w* )
}