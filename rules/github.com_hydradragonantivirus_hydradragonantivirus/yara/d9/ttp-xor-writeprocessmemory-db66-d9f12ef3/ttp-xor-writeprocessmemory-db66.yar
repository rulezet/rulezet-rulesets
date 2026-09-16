rule TTP_XOR_WriteProcessMemory_db66 {
  strings:
    $key_db66 = { 8c 14 [2] be 36 [2] b8 03 [2] 96 03 [2] a9 1f }

  condition:
    any of them
}