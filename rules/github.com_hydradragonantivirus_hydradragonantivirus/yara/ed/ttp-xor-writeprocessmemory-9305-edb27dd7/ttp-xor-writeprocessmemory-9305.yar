rule TTP_XOR_WriteProcessMemory_9305 {
  strings:
    $key_9305 = { c4 77 [2] f6 55 [2] f0 60 [2] de 60 [2] e1 7c }

  condition:
    any of them
}