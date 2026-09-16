rule TTP_XOR_WriteProcessMemory_ef46 {
  strings:
    $key_ef46 = { b8 34 [2] 8a 16 [2] 8c 23 [2] a2 23 [2] 9d 3f }

  condition:
    any of them
}