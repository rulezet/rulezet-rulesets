rule TTP_XOR_WriteProcessMemory_f653 {
  strings:
    $key_f653 = { a1 21 [2] 93 03 [2] 95 36 [2] bb 36 [2] 84 2a }

  condition:
    any of them
}