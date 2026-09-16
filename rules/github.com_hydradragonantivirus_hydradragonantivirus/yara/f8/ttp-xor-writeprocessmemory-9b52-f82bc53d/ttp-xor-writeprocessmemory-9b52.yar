rule TTP_XOR_WriteProcessMemory_9b52 {
  strings:
    $key_9b52 = { cc 20 [2] fe 02 [2] f8 37 [2] d6 37 [2] e9 2b }

  condition:
    any of them
}