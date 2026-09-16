rule TTP_XOR_WriteProcessMemory_9365 {
  strings:
    $key_9365 = { c4 17 [2] f6 35 [2] f0 00 [2] de 00 [2] e1 1c }

  condition:
    any of them
}