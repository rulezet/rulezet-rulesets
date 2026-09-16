rule TTP_XOR_WriteProcessMemory_64e6 {
  strings:
    $key_64e6 = { 33 94 [2] 01 b6 [2] 07 83 [2] 29 83 [2] 16 9f }

  condition:
    any of them
}