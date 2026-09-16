rule TTP_XOR_WriteProcessMemory_1fa6 {
  strings:
    $key_1fa6 = { 48 d4 [2] 7a f6 [2] 7c c3 [2] 52 c3 [2] 6d df }

  condition:
    any of them
}