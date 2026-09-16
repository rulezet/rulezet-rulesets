rule Casper_SystemInformation_Output_RID33C9 : APT DEMO {
   meta:
      description = "Casper French Espionage Malware - System Info Output - https://www.welivesecurity.com/2015/03/05/casper-malware-babar-bunny-another-espionage-cartoon/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2015/03/05/casper-malware-babar-bunny-another-espionage-cartoon/"
      date = "2015-03-06 15:02:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO"
      minimum_yara = "3.5.0"
      
   strings:
      $a0 = "***** SYSTEM INFORMATION ******" 
      $a1 = "***** SECURITY INFORMATION ******" 
      $a2 = "Antivirus: " 
      $a3 = "Firewall: " 
      $a4 = "***** EXECUTION CONTEXT ******" 
      $a5 = "Identity: " 
      $a6 = "<CONFIG TIMESTAMP=" 
   condition: 
      all of them
}