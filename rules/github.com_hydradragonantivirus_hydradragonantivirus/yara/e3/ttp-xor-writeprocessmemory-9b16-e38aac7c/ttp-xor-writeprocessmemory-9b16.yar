rule TTP_XOR_WriteProcessMemory_9b16 {
  strings:
    $key_9b16 = { cc 64 [2] fe 46 [2] f8 73 [2] d6 73 [2] e9 6f }

  condition:
    any of them
}