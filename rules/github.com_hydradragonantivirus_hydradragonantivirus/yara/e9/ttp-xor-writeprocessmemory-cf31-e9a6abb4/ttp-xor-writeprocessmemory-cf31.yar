rule TTP_XOR_WriteProcessMemory_cf31 {
  strings:
    $key_cf31 = { 98 43 [2] aa 61 [2] ac 54 [2] 82 54 [2] bd 48 }

  condition:
    any of them
}