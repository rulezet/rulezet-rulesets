rule TTP_XOR_WriteProcessMemory_6b66 {
  strings:
    $key_6b66 = { 3c 14 [2] 0e 36 [2] 08 03 [2] 26 03 [2] 19 1f }

  condition:
    any of them
}