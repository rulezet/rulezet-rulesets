rule TTP_XOR_WriteProcessMemory_9bdb {
  strings:
    $key_9bdb = { cc a9 [2] fe 8b [2] f8 be [2] d6 be [2] e9 a2 }

  condition:
    any of them
}