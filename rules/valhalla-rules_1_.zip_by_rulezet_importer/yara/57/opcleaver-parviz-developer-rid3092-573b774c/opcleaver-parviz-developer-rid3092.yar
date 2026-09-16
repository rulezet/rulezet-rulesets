rule OPCLEAVER_Parviz_Developer_RID3092 : APT DEMO G0003 {
   meta:
      description = "Parviz developer known from Operation Cleaver"
      author = "Florian Roth"
      reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
      date = "2014-12-02 12:45:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G0003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Users\\parviz\\documents\\" nocase
   condition: 
      $s1
}