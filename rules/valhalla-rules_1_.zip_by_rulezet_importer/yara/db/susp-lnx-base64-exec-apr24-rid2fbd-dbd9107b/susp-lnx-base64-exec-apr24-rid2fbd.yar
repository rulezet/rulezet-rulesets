rule SUSP_LNX_Base64_Exec_Apr24_RID2FBD : CVE_2024_3400 DEMO LINUX SCRIPT SUSP T1105 T1132_001 {
   meta:
      description = "Detects suspicious base64 encoded shell commands (as seen in Palo Alto CVE-2024-3400 exploitation)"
      author = "Christian Burkard"
      reference = "Internal Research"
      date = "2024-04-18 12:10:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2025-03-21"
      id = "2da3d050-86b0-5903-97eb-c5f39ce4f3a3"
      tags = "CVE_2024_3400, DEMO, LINUX, SCRIPT, SUSP, T1105, T1132_001"
      minimum_yara = "4.0.0"
      
   strings:
      $s1 = "curl http://" base64
      $s2 = "wget http://" base64
      $s3 = ";chmod 777 " base64
      $mirai = "country=" 
      $fp1 = "<html" 
      $fp2 = "<?xml" 
   condition: 
      filesize < 800KB and 1 of ( $s* ) and not $mirai and not 1 of ( $fp* )
}