rule TTP_XOR_WriteProcessMemory_7426 {
  strings:
    $key_7426 = { 23 54 [2] 11 76 [2] 17 43 [2] 39 43 [2] 06 5f }

  condition:
    any of them
}