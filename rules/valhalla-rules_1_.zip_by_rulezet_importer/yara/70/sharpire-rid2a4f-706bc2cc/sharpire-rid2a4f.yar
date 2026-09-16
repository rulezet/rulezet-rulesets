rule Sharpire_RID2A4F : DEMO EXE FILE HKTL {
   meta:
      description = "Semiautomatically generated YARA rule - file Sharpire_RID2A4F.exe"
      author = "Florian Roth"
      reference = "https://github.com/0xbadjuju/Sharpire_RID2A4F"
      date = "2017-09-23 05:03:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "327a1dc2876cd9d7f6a5b3777373087296fc809d466e42861adcf09986c6e587"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\obj\\Debug\\Sharpire_RID2A4F.pdb" ascii
      $x2 = "[*] Upload of $fileName successful" fullword wide
      $s1 = "no shell command supplied" fullword wide
      $s2 = "/login/process.php" fullword wide
      $s3 = "invokeShellCommand" fullword ascii
      $s4 = "..Command execution completed." fullword wide
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword wide
      $s6 = "/admin/get.php" fullword wide
      $s7 = "[!] Error in stopping job: " fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and ( 1 of ( $x* ) and 3 of them ) )
}