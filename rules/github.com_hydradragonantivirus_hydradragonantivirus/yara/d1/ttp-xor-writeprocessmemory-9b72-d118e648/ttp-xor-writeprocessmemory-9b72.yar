rule TTP_XOR_WriteProcessMemory_9b72 {
  strings:
    $key_9b72 = { cc 00 [2] fe 22 [2] f8 17 [2] d6 17 [2] e9 0b }

  condition:
    any of them
}