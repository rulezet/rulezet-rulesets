rule TTP_XOR_WriteProcessMemory_6d16 {
  strings:
    $key_6d16 = { 3a 64 [2] 08 46 [2] 0e 73 [2] 20 73 [2] 1f 6f }

  condition:
    any of them
}