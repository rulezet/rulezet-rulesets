rule TTP_XOR_WriteProcessMemory_29f6 {
  strings:
    $key_29f6 = { 7e 84 [2] 4c a6 [2] 4a 93 [2] 64 93 [2] 5b 8f }

  condition:
    any of them
}