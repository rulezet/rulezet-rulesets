rule TTP_XOR_WriteProcessMemory_5582 {
  strings:
    $key_5582 = { 02 f0 [2] 30 d2 [2] 36 e7 [2] 18 e7 [2] 27 fb }

  condition:
    any of them
}