rule Msfpayloads_msf_cmd_RID2ECC : APT DEMO METASPLOIT SCRIPT T1059_001 {
   meta:
      description = "Metasploit Payloads - file msf-cmd.ps1"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 11:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f41932afc9b6b4938ee7a2559067f4df34a5c8eae73558a3959dd677cb5867f"
      tags = "APT, DEMO, METASPLOIT, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e" ascii
   condition: 
      all of them
}