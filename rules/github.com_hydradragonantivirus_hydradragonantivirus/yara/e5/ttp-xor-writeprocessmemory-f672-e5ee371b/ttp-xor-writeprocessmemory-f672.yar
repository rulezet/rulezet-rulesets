rule TTP_XOR_WriteProcessMemory_f672 {
  strings:
    $key_f672 = { a1 00 [2] 93 22 [2] 95 17 [2] bb 17 [2] 84 0b }

  condition:
    any of them
}