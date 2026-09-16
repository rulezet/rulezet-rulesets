rule TTP_XOR_WriteProcessMemory_9b42 {
  strings:
    $key_9b42 = { cc 30 [2] fe 12 [2] f8 27 [2] d6 27 [2] e9 3b }

  condition:
    any of them
}