rule TTP_XOR_WriteProcessMemory_9b75 {
  strings:
    $key_9b75 = { cc 07 [2] fe 25 [2] f8 10 [2] d6 10 [2] e9 0c }

  condition:
    any of them
}