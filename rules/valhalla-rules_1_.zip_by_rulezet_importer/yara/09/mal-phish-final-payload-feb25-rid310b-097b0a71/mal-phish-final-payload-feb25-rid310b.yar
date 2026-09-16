rule MAL_PHISH_Final_Payload_Feb25_RID310B : DEMO MAL T1203 T1566_001 {
   meta:
      description = "Detects possible final payload of phishing-delivered malware, where embedded shellcode is used to decrypt and execute the payload after user-supplied password input."
      author = "X__Junior"
      reference = "https://x.com/dtcert/status/1890384162818802135"
      date = "2025-02-14 13:05:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, MAL, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%lu: %s %s" wide
      $s2 = "(Direct Inbound)" wide
      $s3 = "(Primary Domain)" wide
      $s4 = "(Forest Tree Root" wide
      $s5 = "(Native Mode)" wide
      $s6 = "(In Forest)" wide
      $s7 = "(None)" wide
   condition: 
      all of them
}