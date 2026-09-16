rule TTP_XOR_WriteProcessMemory_9bec {
  strings:
    $key_9bec = { cc 9e [2] fe bc [2] f8 89 [2] d6 89 [2] e9 95 }

  condition:
    any of them
}