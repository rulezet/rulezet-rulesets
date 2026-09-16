rule TTP_XOR_WriteProcessMemory_1fa5 {
  strings:
    $key_1fa5 = { 48 d7 [2] 7a f5 [2] 7c c0 [2] 52 c0 [2] 6d dc }

  condition:
    any of them
}