rule TTP_XOR_WriteProcessMemory_31a0 {
  strings:
    $key_31a0 = { 66 d2 [2] 54 f0 [2] 52 c5 [2] 7c c5 [2] 43 d9 }

  condition:
    any of them
}