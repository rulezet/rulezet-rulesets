rule TTP_XOR_WriteProcessMemory_9b3b {
  strings:
    $key_9b3b = { cc 49 [2] fe 6b [2] f8 5e [2] d6 5e [2] e9 42 }

  condition:
    any of them
}