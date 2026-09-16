rule TTP_XOR_WriteProcessMemory_f667 {
  strings:
    $key_f667 = { a1 15 [2] 93 37 [2] 95 02 [2] bb 02 [2] 84 1e }

  condition:
    any of them
}