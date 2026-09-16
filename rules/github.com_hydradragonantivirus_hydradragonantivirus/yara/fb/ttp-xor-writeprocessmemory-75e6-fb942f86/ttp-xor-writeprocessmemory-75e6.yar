rule TTP_XOR_WriteProcessMemory_75e6 {
  strings:
    $key_75e6 = { 22 94 [2] 10 b6 [2] 16 83 [2] 38 83 [2] 07 9f }

  condition:
    any of them
}