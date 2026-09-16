rule TTP_XOR_WriteProcessMemory_ff96 {
  strings:
    $key_ff96 = { a8 e4 [2] 9a c6 [2] 9c f3 [2] b2 f3 [2] 8d ef }

  condition:
    any of them
}