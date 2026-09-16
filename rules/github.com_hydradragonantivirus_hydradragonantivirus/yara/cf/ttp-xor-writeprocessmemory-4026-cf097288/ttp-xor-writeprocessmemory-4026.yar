rule TTP_XOR_WriteProcessMemory_4026 {
  strings:
    $key_4026 = { 17 54 [2] 25 76 [2] 23 43 [2] 0d 43 [2] 32 5f }

  condition:
    any of them
}