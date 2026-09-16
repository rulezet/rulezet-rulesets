rule TTP_XOR_WriteProcessMemory_12e6 {
  strings:
    $key_12e6 = { 45 94 [2] 77 b6 [2] 71 83 [2] 5f 83 [2] 60 9f }

  condition:
    any of them
}