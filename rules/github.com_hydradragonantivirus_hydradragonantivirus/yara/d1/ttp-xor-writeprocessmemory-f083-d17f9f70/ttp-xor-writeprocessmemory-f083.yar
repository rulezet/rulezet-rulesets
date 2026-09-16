rule TTP_XOR_WriteProcessMemory_f083 {
  strings:
    $key_f083 = { a7 f1 [2] 95 d3 [2] 93 e6 [2] bd e6 [2] 82 fa }

  condition:
    any of them
}