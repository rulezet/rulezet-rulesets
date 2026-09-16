rule MAL_PHISH_Final_Payload_Feb25 {
   meta:
      author = "X__Junior"
      description = "Detects possible final payload of phishing-delivered malware, where embedded shellcode is used to decrypt and execute the payload after user-supplied password input."
      reference = "https://x.com/dtcert/status/1890384162818802135"
      hash = "de384aba6b0c6800095eb530954aa718d4ed96cccfc0b1e5e4d01404f3518a77"
      date = "2025-02-14"
      score = 80
      id = "9014e1f2-09c2-5ba0-8b7c-6ae8c069d1f7"
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