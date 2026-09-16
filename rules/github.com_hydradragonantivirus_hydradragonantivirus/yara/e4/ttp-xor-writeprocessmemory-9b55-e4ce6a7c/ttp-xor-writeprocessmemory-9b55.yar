rule TTP_XOR_WriteProcessMemory_9b55 {
  strings:
    $key_9b55 = { cc 27 [2] fe 05 [2] f8 30 [2] d6 30 [2] e9 2c }

  condition:
    any of them
}