rule TTP_XOR_WriteProcessMemory_9b65 {
  strings:
    $key_9b65 = { cc 17 [2] fe 35 [2] f8 00 [2] d6 00 [2] e9 1c }

  condition:
    any of them
}