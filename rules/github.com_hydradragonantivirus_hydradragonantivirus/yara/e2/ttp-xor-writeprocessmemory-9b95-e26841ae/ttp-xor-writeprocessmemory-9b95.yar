rule TTP_XOR_WriteProcessMemory_9b95 {
  strings:
    $key_9b95 = { cc e7 [2] fe c5 [2] f8 f0 [2] d6 f0 [2] e9 ec }

  condition:
    any of them
}