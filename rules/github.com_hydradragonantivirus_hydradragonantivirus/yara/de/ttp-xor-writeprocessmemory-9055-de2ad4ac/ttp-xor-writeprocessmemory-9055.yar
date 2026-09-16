rule TTP_XOR_WriteProcessMemory_9055 {
  strings:
    $key_9055 = { c7 27 [2] f5 05 [2] f3 30 [2] dd 30 [2] e2 2c }

  condition:
    any of them
}