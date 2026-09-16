rule TTP_XOR_WriteProcessMemory_1fa0 {
  strings:
    $key_1fa0 = { 48 d2 [2] 7a f0 [2] 7c c5 [2] 52 c5 [2] 6d d9 }

  condition:
    any of them
}