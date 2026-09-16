rule TTP_XOR_WriteProcessMemory_9b69 {
  strings:
    $key_9b69 = { cc 1b [2] fe 39 [2] f8 0c [2] d6 0c [2] e9 10 }

  condition:
    any of them
}