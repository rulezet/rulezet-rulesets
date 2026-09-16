rule TTP_XOR_WriteProcessMemory_5992 {
  strings:
    $key_5992 = { 0e e0 [2] 3c c2 [2] 3a f7 [2] 14 f7 [2] 2b eb }

  condition:
    any of them
}