import "pe"
rule APT17_Unsigned_Symantec_Binary_EFA_RID338C : APT DEMO EXE FILE G0025 {
   meta:
      description = "Detects APT17 malware"
      author = "Florian Roth"
      reference = "https://intezer.com/blog/research/evidence-aurora-operation-still-active-part-2-more-ties-uncovered-between-ccleaner-hack-chinese-hackers/"
      date = "2017-10-03 14:52:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "128aca58be325174f0220bd7ca6030e4e206b4378796e82da460055733bb6f4f"
      tags = "APT, DEMO, EXE, FILE, G0025"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Copyright (c) 2007 - 2011 Symantec Corporation" fullword wide
      $s2 = "\\\\.\\SYMEFA" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them and pe.number_of_signatures == 0 )
}