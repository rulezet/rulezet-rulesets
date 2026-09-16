rule TTP_XOR_WriteProcessMemory_9d16 {
  strings:
    $key_9d16 = { ca 64 [2] f8 46 [2] fe 73 [2] d0 73 [2] ef 6f }

  condition:
    any of them
}