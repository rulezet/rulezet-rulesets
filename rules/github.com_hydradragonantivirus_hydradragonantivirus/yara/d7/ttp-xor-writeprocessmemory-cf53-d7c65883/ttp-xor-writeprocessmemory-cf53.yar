rule TTP_XOR_WriteProcessMemory_cf53 {
  strings:
    $key_cf53 = { 98 21 [2] aa 03 [2] ac 36 [2] 82 36 [2] bd 2a }

  condition:
    any of them
}