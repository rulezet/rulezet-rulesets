rule TTP_XOR_WriteProcessMemory_1c16 {
  strings:
    $key_1c16 = { 4b 64 [2] 79 46 [2] 7f 73 [2] 51 73 [2] 6e 6f }

  condition:
    any of them
}