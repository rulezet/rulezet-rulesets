rule TTP_XOR_WriteProcessMemory_f625 {
  strings:
    $key_f625 = { a1 57 [2] 93 75 [2] 95 40 [2] bb 40 [2] 84 5c }

  condition:
    any of them
}