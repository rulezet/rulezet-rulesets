rule TTP_XOR_WriteProcessMemory_f602 {
  strings:
    $key_f602 = { a1 70 [2] 93 52 [2] 95 67 [2] bb 67 [2] 84 7b }

  condition:
    any of them
}