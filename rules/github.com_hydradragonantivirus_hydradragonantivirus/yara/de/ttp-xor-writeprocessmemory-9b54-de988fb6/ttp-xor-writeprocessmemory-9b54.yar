rule TTP_XOR_WriteProcessMemory_9b54 {
  strings:
    $key_9b54 = { cc 26 [2] fe 04 [2] f8 31 [2] d6 31 [2] e9 2d }

  condition:
    any of them
}