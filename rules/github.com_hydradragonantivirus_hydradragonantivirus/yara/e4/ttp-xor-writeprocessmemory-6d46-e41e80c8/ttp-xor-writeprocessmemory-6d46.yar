rule TTP_XOR_WriteProcessMemory_6d46 {
  strings:
    $key_6d46 = { 3a 34 [2] 08 16 [2] 0e 23 [2] 20 23 [2] 1f 3f }

  condition:
    any of them
}