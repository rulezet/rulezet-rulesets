rule OPCLEAVER_CCProxy_Config_RID2F6E : APT DEMO G0003 {
   meta:
      description = "CCProxy config known from Operation Cleaver"
      author = "Florian Roth"
      reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
      date = "2014-12-02 11:56:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, G0003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "UserName=User-001" fullword ascii
      $s2 = "Web=1" fullword ascii
      $s3 = "Mail=1" fullword ascii
      $s4 = "FTP=0" fullword ascii
      $x1 = "IPAddressLow=78.109.194.114" fullword ascii
   condition: 
      all of ( $s* ) or $x1
}