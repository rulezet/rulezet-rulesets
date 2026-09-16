rule TTP_XOR_WriteProcessMemory_9302 {
  strings:
    $key_9302 = { c4 70 [2] f6 52 [2] f0 67 [2] de 67 [2] e1 7b }

  condition:
    any of them
}