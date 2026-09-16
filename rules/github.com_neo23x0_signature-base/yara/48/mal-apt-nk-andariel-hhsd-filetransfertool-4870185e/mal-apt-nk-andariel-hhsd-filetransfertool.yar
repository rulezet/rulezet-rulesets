rule MAL_APT_NK_Andariel_HHSD_FileTransferTool {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the HHSD File Transfer Tool"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      modified = "2025-07-09"
      score = 70
      id = "46b6dbaf-1272-5bbd-a586-5e48ba6c5022"
   strings:
                        $handshake = { 30 ?? ?? 81 7? ?? 22 C0 78 00 4? 88 }
      
                                                      $err_xor_str = { 14 C7 [2] 14 00 41 00 C7 [2] 7A 00 7F 00 C7 [2] 7B 00 63 00 C7 [2] 7A 00 34 00 }
      
                                          $hash_call_loadlib = { B? 8D 10 B7 F8 E8 }
      $hash_call_unk = { B? 91 B8 F6 88 E8 }
      
   condition:
      uint16(0) == 0x5a4d
      and 1 of ($handshake, $err_xor_str) 
      and 1 of ($hash_call_*)
      or 2 of ($handshake, $err_xor_str)
}