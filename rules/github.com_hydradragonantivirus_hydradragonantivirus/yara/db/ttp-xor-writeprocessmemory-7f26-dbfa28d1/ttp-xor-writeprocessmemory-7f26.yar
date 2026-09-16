rule TTP_XOR_WriteProcessMemory_7f26 {
  strings:
    $key_7f26 = { 28 54 [2] 1a 76 [2] 1c 43 [2] 32 43 [2] 0d 5f }

  condition:
    any of them
}