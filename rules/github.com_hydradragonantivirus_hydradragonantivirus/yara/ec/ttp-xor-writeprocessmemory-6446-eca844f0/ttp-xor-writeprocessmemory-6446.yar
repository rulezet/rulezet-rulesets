rule TTP_XOR_WriteProcessMemory_6446 {
  strings:
    $key_6446 = { 33 34 [2] 01 16 [2] 07 23 [2] 29 23 [2] 16 3f }

  condition:
    any of them
}