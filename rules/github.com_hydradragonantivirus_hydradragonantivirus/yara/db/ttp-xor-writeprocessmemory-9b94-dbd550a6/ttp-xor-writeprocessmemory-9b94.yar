rule TTP_XOR_WriteProcessMemory_9b94 {
  strings:
    $key_9b94 = { cc e6 [2] fe c4 [2] f8 f1 [2] d6 f1 [2] e9 ed }

  condition:
    any of them
}