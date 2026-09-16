rule TTP_XOR_WriteProcessMemory_9375 {
  strings:
    $key_9375 = { c4 07 [2] f6 25 [2] f0 10 [2] de 10 [2] e1 0c }

  condition:
    any of them
}