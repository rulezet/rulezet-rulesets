rule TTP_XOR_WriteProcessMemory_5a80 {
  strings:
    $key_5a80 = { 0d f2 [2] 3f d0 [2] 39 e5 [2] 17 e5 [2] 28 f9 }

  condition:
    any of them
}