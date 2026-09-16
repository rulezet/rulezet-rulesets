rule TTP_XOR_WriteProcessMemory_1a80 {
  strings:
    $key_1a80 = { 4d f2 [2] 7f d0 [2] 79 e5 [2] 57 e5 [2] 68 f9 }

  condition:
    any of them
}