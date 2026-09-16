rule TTP_XOR_WriteProcessMemory_02e6 {
  strings:
    $key_02e6 = { 55 94 [2] 67 b6 [2] 61 83 [2] 4f 83 [2] 70 9f }

  condition:
    any of them
}