rule TTP_XOR_WriteProcessMemory_1f92 {
  strings:
    $key_1f92 = { 48 e0 [2] 7a c2 [2] 7c f7 [2] 52 f7 [2] 6d eb }

  condition:
    any of them
}