rule TTP_XOR_WriteProcessMemory_f572 {
  strings:
    $key_f572 = { a2 00 [2] 90 22 [2] 96 17 [2] b8 17 [2] 87 0b }

  condition:
    any of them
}