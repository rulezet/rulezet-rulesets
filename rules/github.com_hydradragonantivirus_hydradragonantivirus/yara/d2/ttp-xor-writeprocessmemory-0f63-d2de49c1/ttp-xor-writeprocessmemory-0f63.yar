rule TTP_XOR_WriteProcessMemory_0f63 {
  strings:
    $key_0f63 = { 58 11 [2] 6a 33 [2] 6c 06 [2] 42 06 [2] 7d 1a }

  condition:
    any of them
}