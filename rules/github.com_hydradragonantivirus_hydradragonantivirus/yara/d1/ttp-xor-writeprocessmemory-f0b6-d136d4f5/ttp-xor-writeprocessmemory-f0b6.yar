rule TTP_XOR_WriteProcessMemory_f0b6 {
  strings:
    $key_f0b6 = { a7 c4 [2] 95 e6 [2] 93 d3 [2] bd d3 [2] 82 cf }

  condition:
    any of them
}