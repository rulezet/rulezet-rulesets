rule TTP_XOR_WriteProcessMemory_7436 {
  strings:
    $key_7436 = { 23 44 [2] 11 66 [2] 17 53 [2] 39 53 [2] 06 4f }

  condition:
    any of them
}