rule TTP_XOR_WriteProcessMemory_4306 {
  strings:
    $key_4306 = { 14 74 [2] 26 56 [2] 20 63 [2] 0e 63 [2] 31 7f }

  condition:
    any of them
}