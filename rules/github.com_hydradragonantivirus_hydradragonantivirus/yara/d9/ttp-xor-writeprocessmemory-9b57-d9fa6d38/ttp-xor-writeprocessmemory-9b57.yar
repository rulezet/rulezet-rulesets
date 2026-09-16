rule TTP_XOR_WriteProcessMemory_9b57 {
  strings:
    $key_9b57 = { cc 25 [2] fe 07 [2] f8 32 [2] d6 32 [2] e9 2e }

  condition:
    any of them
}