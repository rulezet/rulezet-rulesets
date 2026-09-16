rule KeeTheft_EXE_RID2B62 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects component of KeeTheft - KeePass dump tool - file KeeTheft.exe"
      author = "Florian Roth"
      reference = "https://github.com/HarmJ0y/KeeThief"
      date = "2017-08-29 09:04:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f06789c3e9fe93c165889799608e59dda6b10331b931601c2b5ae06ede41dc22"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Error: Could not create a thread for the shellcode" fullword wide
      $x2 = "Could not find address marker in shellcode" fullword wide
      $x3 = "GenerateDecryptionShellCode" fullword ascii
      $x4 = "KeePassLib.Keys.KcpPassword" fullword wide
      $x5 = "************ Found a CompositeKey! **********" fullword wide
      $x6 = "*** Interesting... there are multiple .NET runtimes loaded in KeePass" fullword wide
      $x7 = "GetKcpPasswordInfo" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 2 of them )
}