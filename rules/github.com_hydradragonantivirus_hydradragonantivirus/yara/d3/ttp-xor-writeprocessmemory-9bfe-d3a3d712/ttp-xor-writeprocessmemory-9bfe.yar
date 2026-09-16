rule TTP_XOR_WriteProcessMemory_9bfe {
  strings:
    $key_9bfe = { cc 8c [2] fe ae [2] f8 9b [2] d6 9b [2] e9 87 }

  condition:
    any of them
}