rule TTP_XOR_WriteProcessMemory_9b9d {
  strings:
    $key_9b9d = { cc ef [2] fe cd [2] f8 f8 [2] d6 f8 [2] e9 e4 }

  condition:
    any of them
}