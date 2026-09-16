rule MAL_PHISH_ShellCode_Enc_Payload_Feb25 {
   meta:
      author = "X__Junior"
      description = "Detects unknown of phishing-delivered malware"
      reference = "https://x.com/dtcert/status/1890384162818802135"
      hash = "247e6a648bb22d35095ba02ef4af8cfe0a4cdfa25271117414ff2e3a21021886"
      date = "2025-02-14"
      score = 80
      id = "8459c5ba-37ec-59bd-8d4a-5ab7b6bb4553"
   strings:
     $op1 = { 48 89 EA FF D0 48 89 E9 4C 8D 4C 24 ?? 41 B8 ?? ?? ?? ?? 48 89 C7 48 89 C3 48 89 EA F3 A4 48 89 C1 41 FF D4 31 C9 FF D3}
   condition:
      uint16(0) == 0x5a4d and $op1
}