rule p0wnedAmsiBypass_RID2D5B : DEMO HKTL {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedAmsiBypass_RID2D5B.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14 10:28:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "345e8e6f38b2914f4533c4c16421d372d61564a4275537e674a2ac3360b19284"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Program.P0wnedPath()" fullword ascii
      $x2 = "namespace p0wnedShell" fullword ascii
      $x3 = "H4sIAAAAAAAEAO1YfXRUx3WflXalFazQgiVb5nMVryzxIbGrt/rcFRZIa1CQYEFCQnxotUhP2pX3Q337HpYotCKrPdbmoQQnkOY0+BQCNKRpe" ascii
   condition: 
      1 of them
}