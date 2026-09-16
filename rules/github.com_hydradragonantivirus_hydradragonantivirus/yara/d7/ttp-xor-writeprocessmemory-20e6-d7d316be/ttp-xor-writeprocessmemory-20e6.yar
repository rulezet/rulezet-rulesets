rule TTP_XOR_WriteProcessMemory_20e6 {
  strings:
    $key_20e6 = { 77 94 [2] 45 b6 [2] 43 83 [2] 6d 83 [2] 52 9f }

  condition:
    any of them
}