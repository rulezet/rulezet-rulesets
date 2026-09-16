rule TTP_XOR_WriteProcessMemory_f783 {
  strings:
    $key_f783 = { a0 f1 [2] 92 d3 [2] 94 e6 [2] ba e6 [2] 85 fa }

  condition:
    any of them
}