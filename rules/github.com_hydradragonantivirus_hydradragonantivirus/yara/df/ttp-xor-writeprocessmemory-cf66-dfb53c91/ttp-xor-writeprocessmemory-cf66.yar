rule TTP_XOR_WriteProcessMemory_cf66 {
  strings:
    $key_cf66 = { 98 14 [2] aa 36 [2] ac 03 [2] 82 03 [2] bd 1f }

  condition:
    any of them
}