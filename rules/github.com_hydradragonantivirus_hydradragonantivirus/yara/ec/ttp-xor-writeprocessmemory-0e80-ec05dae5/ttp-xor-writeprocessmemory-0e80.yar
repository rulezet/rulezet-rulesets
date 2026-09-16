rule TTP_XOR_WriteProcessMemory_0e80 {
  strings:
    $key_0e80 = { 59 f2 [2] 6b d0 [2] 6d e5 [2] 43 e5 [2] 7c f9 }

  condition:
    any of them
}