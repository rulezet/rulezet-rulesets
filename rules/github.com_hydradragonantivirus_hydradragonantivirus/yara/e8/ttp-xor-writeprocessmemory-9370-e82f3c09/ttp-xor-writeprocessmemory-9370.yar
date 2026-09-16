rule TTP_XOR_WriteProcessMemory_9370 {
  strings:
    $key_9370 = { c4 02 [2] f6 20 [2] f0 15 [2] de 15 [2] e1 09 }

  condition:
    any of them
}