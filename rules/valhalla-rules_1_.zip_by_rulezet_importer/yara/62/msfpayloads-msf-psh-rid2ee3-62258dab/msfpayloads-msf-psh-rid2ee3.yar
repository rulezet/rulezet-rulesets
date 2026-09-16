rule Msfpayloads_msf_psh_RID2EE3 : APT DEMO METASPLOIT SCRIPT {
   meta:
      description = "Metasploit Payloads - file msf-psh.vba"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 11:33:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5cc6c7f1aa75df8979be4a16e36cece40340c6e192ce527771bdd6463253e46f"
      tags = "APT, DEMO, METASPLOIT, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "powershell.exe -nop -w hidden -e" ascii
      $s2 = "Call Shell(" ascii
      $s3 = "Sub Workbook_Open()" fullword ascii
   condition: 
      all of them
}