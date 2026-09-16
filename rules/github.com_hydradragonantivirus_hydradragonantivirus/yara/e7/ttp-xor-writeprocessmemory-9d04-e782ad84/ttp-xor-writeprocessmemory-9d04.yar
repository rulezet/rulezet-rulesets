rule TTP_XOR_WriteProcessMemory_9d04 {
  strings:
    $key_9d04 = { ca 76 [2] f8 54 [2] fe 61 [2] d0 61 [2] ef 7d }

  condition:
    any of them
}