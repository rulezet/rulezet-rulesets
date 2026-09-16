rule TTP_XOR_WriteProcessMemory_9b3c {
  strings:
    $key_9b3c = { cc 4e [2] fe 6c [2] f8 59 [2] d6 59 [2] e9 45 }

  condition:
    any of them
}