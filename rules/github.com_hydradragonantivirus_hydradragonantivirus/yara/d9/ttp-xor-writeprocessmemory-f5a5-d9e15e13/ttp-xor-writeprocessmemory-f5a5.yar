rule TTP_XOR_WriteProcessMemory_f5a5 {
  strings:
    $key_f5a5 = { a2 d7 [2] 90 f5 [2] 96 c0 [2] b8 c0 [2] 87 dc }

  condition:
    any of them
}