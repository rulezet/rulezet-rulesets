rule TTP_XOR_WriteProcessMemory_f7a5 {
  strings:
    $key_f7a5 = { a0 d7 [2] 92 f5 [2] 94 c0 [2] ba c0 [2] 85 dc }

  condition:
    any of them
}