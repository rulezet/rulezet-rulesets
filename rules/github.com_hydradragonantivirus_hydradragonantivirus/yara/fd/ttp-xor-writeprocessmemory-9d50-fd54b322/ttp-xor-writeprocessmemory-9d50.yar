rule TTP_XOR_WriteProcessMemory_9d50 {
  strings:
    $key_9d50 = { ca 22 [2] f8 00 [2] fe 35 [2] d0 35 [2] ef 29 }

  condition:
    any of them
}