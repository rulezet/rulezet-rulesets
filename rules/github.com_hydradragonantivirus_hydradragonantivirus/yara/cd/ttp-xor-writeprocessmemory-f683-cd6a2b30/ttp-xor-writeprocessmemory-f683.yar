rule TTP_XOR_WriteProcessMemory_f683 {
  strings:
    $key_f683 = { a1 f1 [2] 93 d3 [2] 95 e6 [2] bb e6 [2] 84 fa }

  condition:
    any of them
}