rule TTP_XOR_WriteProcessMemory_9b36 {
  strings:
    $key_9b36 = { cc 44 [2] fe 66 [2] f8 53 [2] d6 53 [2] e9 4f }

  condition:
    any of them
}