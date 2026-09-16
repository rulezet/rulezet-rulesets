rule TTP_XOR_WriteProcessMemory_56e6 {
  strings:
    $key_56e6 = { 01 94 [2] 33 b6 [2] 35 83 [2] 1b 83 [2] 24 9f }

  condition:
    any of them
}