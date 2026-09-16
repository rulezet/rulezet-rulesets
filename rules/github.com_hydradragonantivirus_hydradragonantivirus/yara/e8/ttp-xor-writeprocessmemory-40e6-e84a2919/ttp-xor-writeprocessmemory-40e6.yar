rule TTP_XOR_WriteProcessMemory_40e6 {
  strings:
    $key_40e6 = { 17 94 [2] 25 b6 [2] 23 83 [2] 0d 83 [2] 32 9f }

  condition:
    any of them
}