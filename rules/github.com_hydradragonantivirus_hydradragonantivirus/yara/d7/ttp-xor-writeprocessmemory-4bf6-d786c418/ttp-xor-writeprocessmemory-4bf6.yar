rule TTP_XOR_WriteProcessMemory_4bf6 {
  strings:
    $key_4bf6 = { 1c 84 [2] 2e a6 [2] 28 93 [2] 06 93 [2] 39 8f }

  condition:
    any of them
}