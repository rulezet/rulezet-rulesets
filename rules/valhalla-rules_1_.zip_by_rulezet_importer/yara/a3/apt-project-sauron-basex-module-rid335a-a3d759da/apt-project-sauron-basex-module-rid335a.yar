rule APT_Project_Sauron_basex_module_RID335A : APT DEMO G0041 {
   meta:
      description = "Detects strings from basex module - Project Sauron report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2016-08-08 14:44:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, G0041"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "64, 64url, 32, 32url or 16." 
      $s2 = "Force decoding when input is invalid/corrupt" 
      $s3 = "This cruft" 
   condition: 
      $x1 or 2 of them
}