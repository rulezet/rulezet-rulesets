rule TTP_XOR_WriteProcessMemory_9b2e {
  strings:
    $key_9b2e = { cc 5c [2] fe 7e [2] f8 4b [2] d6 4b [2] e9 57 }

  condition:
    any of them
}