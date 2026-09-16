rule TTP_XOR_WriteProcessMemory_9b63 {
  strings:
    $key_9b63 = { cc 11 [2] fe 33 [2] f8 06 [2] d6 06 [2] e9 1a }

  condition:
    any of them
}