rule TTP_XOR_WriteProcessMemory_7ff6 {
  strings:
    $key_7ff6 = { 28 84 [2] 1a a6 [2] 1c 93 [2] 32 93 [2] 0d 8f }

  condition:
    any of them
}