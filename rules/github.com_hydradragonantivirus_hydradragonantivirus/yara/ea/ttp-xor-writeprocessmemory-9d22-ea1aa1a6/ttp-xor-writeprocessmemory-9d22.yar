rule TTP_XOR_WriteProcessMemory_9d22 {
  strings:
    $key_9d22 = { ca 50 [2] f8 72 [2] fe 47 [2] d0 47 [2] ef 5b }

  condition:
    any of them
}