rule TTP_XOR_WriteProcessMemory_9655 {
  strings:
    $key_9655 = { c1 27 [2] f3 05 [2] f5 30 [2] db 30 [2] e4 2c }

  condition:
    any of them
}