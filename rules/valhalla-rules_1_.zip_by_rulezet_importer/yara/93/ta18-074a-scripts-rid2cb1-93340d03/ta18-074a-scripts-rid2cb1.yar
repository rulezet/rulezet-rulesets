rule TA18_074A_scripts_RID2CB1 : APT DEMO {
   meta:
      description = "Detects malware mentioned in TA18-074A"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
      date = "2018-03-16 10:00:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-08-18"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Running -s cmd /c query user on " ascii
   condition: 
      filesize < 600KB and 1 of them
}