rule APT_Project_Sauron_dext_module_RID32FC : APT DEMO G0041 {
   meta:
      description = "Detects strings from dext module - Project Sauron report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2016-08-08 14:28:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, G0041"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Assemble rows of DNS names back to a single string of data" 
      $x2 = "removes checks of DNS names and lengths (during split)" 
      $x3 = "Randomize data lengths (length/2 to length)" 
      $x4 = "This cruft" 
   condition: 
      2 of them
}