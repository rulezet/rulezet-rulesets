rule TTP_XOR_WriteProcessMemory_7fa0 {
  strings:
    $key_7fa0 = { 28 d2 [2] 1a f0 [2] 1c c5 [2] 32 c5 [2] 0d d9 }

  condition:
    any of them
}