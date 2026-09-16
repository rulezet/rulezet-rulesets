rule TTP_XOR_WriteProcessMemory_9b19 {
  strings:
    $key_9b19 = { cc 6b [2] fe 49 [2] f8 7c [2] d6 7c [2] e9 60 }

  condition:
    any of them
}