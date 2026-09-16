rule TTP_XOR_WriteProcessMemory_9d40 {
  strings:
    $key_9d40 = { ca 32 [2] f8 10 [2] fe 25 [2] d0 25 [2] ef 39 }

  condition:
    any of them
}