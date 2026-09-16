rule TTP_XOR_WriteProcessMemory_9b59 {
  strings:
    $key_9b59 = { cc 2b [2] fe 09 [2] f8 3c [2] d6 3c [2] e9 20 }

  condition:
    any of them
}