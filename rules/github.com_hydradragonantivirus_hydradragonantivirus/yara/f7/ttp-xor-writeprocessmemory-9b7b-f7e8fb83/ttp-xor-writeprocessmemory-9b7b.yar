rule TTP_XOR_WriteProcessMemory_9b7b {
  strings:
    $key_9b7b = { cc 09 [2] fe 2b [2] f8 1e [2] d6 1e [2] e9 02 }

  condition:
    any of them
}