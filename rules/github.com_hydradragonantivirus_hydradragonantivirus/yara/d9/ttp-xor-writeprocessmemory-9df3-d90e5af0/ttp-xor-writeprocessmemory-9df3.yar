rule TTP_XOR_WriteProcessMemory_9df3 {
  strings:
    $key_9df3 = { ca 81 [2] f8 a3 [2] fe 96 [2] d0 96 [2] ef 8a }

  condition:
    any of them
}