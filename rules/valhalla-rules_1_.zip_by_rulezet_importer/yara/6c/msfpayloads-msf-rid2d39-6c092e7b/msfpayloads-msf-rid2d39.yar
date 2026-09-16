rule Msfpayloads_msf_RID2D39 : APT DEMO METASPLOIT SCRIPT {
   meta:
      description = "Metasploit Payloads - file msf.sh"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:22:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-08-18"
      hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
      tags = "APT, DEMO, METASPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "export buf=\\" ascii
   condition: 
      filesize < 5MB and $s1
}