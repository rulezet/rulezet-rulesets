rule MAL_RANSOM_SH_ESXi_Attacks_Feb23_2_RID3258 : CRIME DEMO MAL RANSOM SCRIPT {
   meta:
      description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers"
      author = "Florian Roth"
      reference = "https://dev.to/xakrume/esxiargs-encryption-malware-launches-massive-attacks-against-vmware-esxi-servers-pfe"
      date = "2023-02-06 14:01:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CRIME, DEMO, MAL, RANSOM, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "echo \"START ENCRYPT: $file_e SIZE: $size_kb STEP SIZE: " ascii
   condition: 
      filesize < 10KB and 1 of them
}