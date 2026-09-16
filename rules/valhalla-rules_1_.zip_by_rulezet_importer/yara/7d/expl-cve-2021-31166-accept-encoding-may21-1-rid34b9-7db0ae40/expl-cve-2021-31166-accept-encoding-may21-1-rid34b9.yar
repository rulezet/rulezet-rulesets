rule EXPL_CVE_2021_31166_Accept_Encoding_May21_1_RID34B9 : CVE_2021_31166 DEMO EXPLOIT {
   meta:
      description = "Detects malformed Accept-Encoding header field as used in code exploiting CVE-2021-31166"
      author = "Florian Roth"
      reference = "https://github.com/0vercl0k/CVE-2021-31166"
      date = "2021-05-21 15:42:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2021_31166, DEMO, EXPLOIT"
      minimum_yara = "3.5.0"
      
   strings:
      $xr1 = /[Aa]ccept\-[Ee]ncoding: [a-z\-]{1,16},([a-z\-\s]{1,16},|)*[\s]{1,20},/ 
   condition: 
      1 of them
}