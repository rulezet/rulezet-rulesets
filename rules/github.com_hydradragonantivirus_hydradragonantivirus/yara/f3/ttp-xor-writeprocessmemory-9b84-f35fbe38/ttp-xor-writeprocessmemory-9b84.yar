rule TTP_XOR_WriteProcessMemory_9b84 {
  strings:
    $key_9b84 = { cc f6 [2] fe d4 [2] f8 e1 [2] d6 e1 [2] e9 fd }

  condition:
    any of them
}