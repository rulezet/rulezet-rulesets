rule p0wnedShell_outputs_RID2EDA : DEMO HKTL {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - from files p0wnedShell.cs, p0wnedShell.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14 11:32:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[+] For this attack to succeed, you need to have Admin privileges." fullword ascii
      $s2 = "[+] This is not a valid hostname, please try again" fullword ascii
      $s3 = "[+] First return the name of our current domain." fullword ascii
   condition: 
      1 of them
}