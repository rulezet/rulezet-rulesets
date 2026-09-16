rule TTP_XOR_WriteProcessMemory_9d71 {
  strings:
    $key_9d71 = { ca 03 [2] f8 21 [2] fe 14 [2] d0 14 [2] ef 08 }

  condition:
    any of them
}