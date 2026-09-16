rule HKTL_Dsniff_RID2AFD : APT DEMO HKTL {
   meta:
      description = "Detects Dsniff hack tool"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2019-02-19 08:47:21"
      score = 55
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = ".*account.*|.*acct.*|.*domain.*|.*login.*|.*member.*" 
   condition: 
      1 of them
}