rule TTP_XOR_WriteProcessMemory_f5a7 {
  strings:
    $key_f5a7 = { a2 d5 [2] 90 f7 [2] 96 c2 [2] b8 c2 [2] 87 de }

  condition:
    any of them
}