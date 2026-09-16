rule TTP_XOR_WriteProcessMemory_cf61 {
  strings:
    $key_cf61 = { 98 13 [2] aa 31 [2] ac 04 [2] 82 04 [2] bd 18 }

  condition:
    any of them
}