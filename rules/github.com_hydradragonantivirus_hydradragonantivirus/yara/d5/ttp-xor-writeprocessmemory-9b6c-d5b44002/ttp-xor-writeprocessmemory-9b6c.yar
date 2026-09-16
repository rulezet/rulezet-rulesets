rule TTP_XOR_WriteProcessMemory_9b6c {
  strings:
    $key_9b6c = { cc 1e [2] fe 3c [2] f8 09 [2] d6 09 [2] e9 15 }

  condition:
    any of them
}