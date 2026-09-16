rule TTP_XOR_WriteProcessMemory_9b20 {
  strings:
    $key_9b20 = { cc 52 [2] fe 70 [2] f8 45 [2] d6 45 [2] e9 59 }

  condition:
    any of them
}