rule TTP_XOR_WriteProcessMemory_82bb {
  strings:
    $key_82bb = { d5 c9 [2] e7 eb [2] e1 de [2] cf de [2] f0 c2 }

  condition:
    any of them
}