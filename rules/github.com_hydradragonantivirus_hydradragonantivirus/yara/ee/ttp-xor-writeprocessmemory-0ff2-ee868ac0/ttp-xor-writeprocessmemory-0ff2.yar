rule TTP_XOR_WriteProcessMemory_0ff2 {
  strings:
    $key_0ff2 = { 58 80 [2] 6a a2 [2] 6c 97 [2] 42 97 [2] 7d 8b }

  condition:
    any of them
}