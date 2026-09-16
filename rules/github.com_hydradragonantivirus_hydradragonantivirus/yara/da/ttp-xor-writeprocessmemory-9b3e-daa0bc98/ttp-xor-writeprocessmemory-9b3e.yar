rule TTP_XOR_WriteProcessMemory_9b3e {
  strings:
    $key_9b3e = { cc 4c [2] fe 6e [2] f8 5b [2] d6 5b [2] e9 47 }

  condition:
    any of them
}