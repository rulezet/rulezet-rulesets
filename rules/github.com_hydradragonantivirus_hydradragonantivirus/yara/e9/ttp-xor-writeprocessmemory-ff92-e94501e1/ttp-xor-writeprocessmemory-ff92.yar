rule TTP_XOR_WriteProcessMemory_ff92 {
  strings:
    $key_ff92 = { a8 e0 [2] 9a c2 [2] 9c f7 [2] b2 f7 [2] 8d eb }

  condition:
    any of them
}