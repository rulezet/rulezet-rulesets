rule Msfpayloads_msf_exe_RID2EDA : APT DEMO METASPLOIT SCRIPT {
   meta:
      description = "Metasploit Payloads - file msf-exe.vba"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 11:32:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "321537007ea5052a43ffa46a6976075cee6a4902af0c98b9fd711b9f572c20fd"
      tags = "APT, DEMO, METASPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "'* PAYLOAD DATA" fullword ascii
      $s2 = " = Shell(" ascii
      $s3 = "= Environ(\"USERPROFILE\")" fullword ascii
      $s4 = "'**************************************************************" fullword ascii
      $s5 = "ChDir (" ascii
      $s6 = "'* MACRO CODE" fullword ascii
   condition: 
      4 of them
}