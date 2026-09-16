rule TTP_XOR_WriteProcessMemory_15e6 {
  strings:
    $key_15e6 = { 42 94 [2] 70 b6 [2] 76 83 [2] 58 83 [2] 67 9f }

  condition:
    any of them
}