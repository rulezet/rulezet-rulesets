rule TTP_XOR_WriteProcessMemory_9d96 {
  strings:
    $key_9d96 = { ca e4 [2] f8 c6 [2] fe f3 [2] d0 f3 [2] ef ef }

  condition:
    any of them
}