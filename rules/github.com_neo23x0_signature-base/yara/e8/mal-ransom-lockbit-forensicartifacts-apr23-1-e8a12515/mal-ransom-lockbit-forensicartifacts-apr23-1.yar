rule MAL_RANSOM_LockBit_ForensicArtifacts_Apr23_1 {
   meta:
      description = "Detects forensic artifacts found in LockBit intrusions"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17"
      score = 75
      id = "e716030c-ee78-51dc-919c-cf59e93da976"
   strings:
      $x1 = "/tmp/locker.log" ascii fullword
      $x2 = "Executable=LockBit/locker_" ascii
      
      $xc1 = { 54 6F 72 20 42 72 6F 77 73 65 72 20 4C 69 6E 6B 73 3A 0D 0A 68 74 74 70 3A 2F 2F 6C 6F 63 6B 62 69 74 }
   condition:
      1 of ($x*)
}