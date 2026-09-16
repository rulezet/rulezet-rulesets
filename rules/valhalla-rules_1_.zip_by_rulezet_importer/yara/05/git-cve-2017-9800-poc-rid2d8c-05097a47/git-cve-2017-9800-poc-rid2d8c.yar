rule git_CVE_2017_9800_poc_RID2D8C : CVE_2017_9800 DEMO SUSP {
   meta:
      description = "Detects a CVE-2017-9800 exploitation attempt"
      author = "Florian Roth"
      reference = "https://twitter.com/mzbat/status/895811803325898753"
      date = "2017-08-11 10:36:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2017_9800, DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "git clone ssh://-oProxyCommand=" ascii
      $s2 = "git clone http://-" ascii
      $s3 = "git clone https://-" ascii
   condition: 
      filesize < 200KB and 1 of them
}