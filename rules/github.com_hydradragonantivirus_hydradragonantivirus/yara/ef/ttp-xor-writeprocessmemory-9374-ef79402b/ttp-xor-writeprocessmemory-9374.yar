rule TTP_XOR_WriteProcessMemory_9374 {
  strings:
    $key_9374 = { c4 06 [2] f6 24 [2] f0 11 [2] de 11 [2] e1 0d }

  condition:
    any of them
}