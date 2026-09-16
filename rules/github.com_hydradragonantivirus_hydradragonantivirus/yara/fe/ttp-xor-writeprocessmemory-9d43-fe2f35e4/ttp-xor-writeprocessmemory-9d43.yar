rule TTP_XOR_WriteProcessMemory_9d43 {
  strings:
    $key_9d43 = { ca 31 [2] f8 13 [2] fe 26 [2] d0 26 [2] ef 3a }

  condition:
    any of them
}