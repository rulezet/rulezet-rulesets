rule TTP_XOR_WriteProcessMemory_9bc1 {
  strings:
    $key_9bc1 = { cc b3 [2] fe 91 [2] f8 a4 [2] d6 a4 [2] e9 b8 }

  condition:
    any of them
}