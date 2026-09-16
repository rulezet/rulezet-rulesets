rule TTP_XOR_WriteProcessMemory_f612 {
  strings:
    $key_f612 = { a1 60 [2] 93 42 [2] 95 77 [2] bb 77 [2] 84 6b }

  condition:
    any of them
}