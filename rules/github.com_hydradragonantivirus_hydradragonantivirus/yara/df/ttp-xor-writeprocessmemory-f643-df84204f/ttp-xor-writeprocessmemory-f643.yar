rule TTP_XOR_WriteProcessMemory_f643 {
  strings:
    $key_f643 = { a1 31 [2] 93 13 [2] 95 26 [2] bb 26 [2] 84 3a }

  condition:
    any of them
}