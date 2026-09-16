rule WPR_Passscape_Loader_RID2EC2 : DEMO EXE FILE HKTL T1543_003 {
   meta:
      description = "Windows Password Recovery - file ast.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15 11:28:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f6f2d4b9f19f9311ec419f05224a1c17cf2449f2027cb7738294479eea56e9cb"
      tags = "DEMO, EXE, FILE, HKTL, T1543_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\PasscapeLoader64" fullword wide
      $s2 = "ast64.dll" fullword ascii
      $s3 = "\\loader64.exe" wide
      $s4 = "Passcape 64-bit Loader Service" fullword wide
      $s5 = "PasscapeLoader64" fullword wide
      $s6 = "ast64 {msg1GkjN7Sh8sg2Al7ker63f}" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}