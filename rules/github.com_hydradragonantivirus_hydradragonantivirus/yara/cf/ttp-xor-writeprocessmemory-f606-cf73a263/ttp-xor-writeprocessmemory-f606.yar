rule TTP_XOR_WriteProcessMemory_f606 {
  strings:
    $key_f606 = { a1 74 [2] 93 56 [2] 95 63 [2] bb 63 [2] 84 7f }

  condition:
    any of them
}