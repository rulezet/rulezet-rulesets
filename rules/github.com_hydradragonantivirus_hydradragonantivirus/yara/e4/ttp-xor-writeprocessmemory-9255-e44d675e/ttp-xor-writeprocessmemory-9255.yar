rule TTP_XOR_WriteProcessMemory_9255 {
  strings:
    $key_9255 = { c5 27 [2] f7 05 [2] f1 30 [2] df 30 [2] e0 2c }

  condition:
    any of them
}