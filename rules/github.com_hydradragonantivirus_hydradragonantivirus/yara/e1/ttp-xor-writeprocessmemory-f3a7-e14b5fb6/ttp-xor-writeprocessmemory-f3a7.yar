rule TTP_XOR_WriteProcessMemory_f3a7 {
  strings:
    $key_f3a7 = { a4 d5 [2] 96 f7 [2] 90 c2 [2] be c2 [2] 81 de }

  condition:
    any of them
}