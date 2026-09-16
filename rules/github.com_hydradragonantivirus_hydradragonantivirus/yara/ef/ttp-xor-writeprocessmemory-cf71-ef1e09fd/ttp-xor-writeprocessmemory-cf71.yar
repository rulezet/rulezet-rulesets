rule TTP_XOR_WriteProcessMemory_cf71 {
  strings:
    $key_cf71 = { 98 03 [2] aa 21 [2] ac 14 [2] 82 14 [2] bd 08 }

  condition:
    any of them
}