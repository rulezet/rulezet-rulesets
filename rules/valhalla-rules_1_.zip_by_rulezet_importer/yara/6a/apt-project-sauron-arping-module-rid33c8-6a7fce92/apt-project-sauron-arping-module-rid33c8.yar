rule APT_Project_Sauron_arping_module_RID33C8 : APT DEMO G0041 {
   meta:
      description = "Detects strings from arping module - Project Sauron report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2016-08-08 15:02:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, G0041"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Resolve hosts that answer" 
      $s2 = "Print only replying Ips" 
      $s3 = "Do not display MAC addresses" 
   condition: 
      all of them
}