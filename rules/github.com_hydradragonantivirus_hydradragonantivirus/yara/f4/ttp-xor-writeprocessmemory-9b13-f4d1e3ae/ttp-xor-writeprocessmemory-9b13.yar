rule TTP_XOR_WriteProcessMemory_9b13 {
  strings:
    $key_9b13 = { cc 61 [2] fe 43 [2] f8 76 [2] d6 76 [2] e9 6a }

  condition:
    any of them
}