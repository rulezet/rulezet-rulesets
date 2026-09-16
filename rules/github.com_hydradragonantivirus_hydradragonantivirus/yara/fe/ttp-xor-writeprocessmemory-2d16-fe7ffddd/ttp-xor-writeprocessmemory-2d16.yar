rule TTP_XOR_WriteProcessMemory_2d16 {
  strings:
    $key_2d16 = { 7a 64 [2] 48 46 [2] 4e 73 [2] 60 73 [2] 5f 6f }

  condition:
    any of them
}