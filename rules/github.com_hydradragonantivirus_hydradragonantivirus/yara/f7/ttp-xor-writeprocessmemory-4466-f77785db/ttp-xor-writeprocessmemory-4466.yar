rule TTP_XOR_WriteProcessMemory_4466 {
  strings:
    $key_4466 = { 13 14 [2] 21 36 [2] 27 03 [2] 09 03 [2] 36 1f }

  condition:
    any of them
}