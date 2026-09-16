rule TTP_XOR_WriteProcessMemory_6466 {
  strings:
    $key_6466 = { 33 14 [2] 01 36 [2] 07 03 [2] 29 03 [2] 16 1f }

  condition:
    any of them
}