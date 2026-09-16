rule TTP_XOR_WriteProcessMemory_9bf9 {
  strings:
    $key_9bf9 = { cc 8b [2] fe a9 [2] f8 9c [2] d6 9c [2] e9 80 }

  condition:
    any of them
}