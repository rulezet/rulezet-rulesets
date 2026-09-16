rule TTP_XOR_WriteProcessMemory_9d73 {
  strings:
    $key_9d73 = { ca 01 [2] f8 23 [2] fe 16 [2] d0 16 [2] ef 0a }

  condition:
    any of them
}