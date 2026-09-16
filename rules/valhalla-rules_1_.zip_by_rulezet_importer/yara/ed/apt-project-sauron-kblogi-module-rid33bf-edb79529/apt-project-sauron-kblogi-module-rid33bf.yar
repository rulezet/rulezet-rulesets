rule APT_Project_Sauron_kblogi_module_RID33BF : APT DEMO G0041 {
   meta:
      description = "Detects strings from kblogi module - Project Sauron report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2016-08-08 15:01:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, G0041"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Inject using process name or pid. Default" 
      $s2 = "Convert mode: Read log from file and convert to text" 
      $s3 = "Maximum running time in seconds" 
   condition: 
      $x1 or 2 of them
}