rule TTP_XOR_WriteProcessMemory_9d76 {
  strings:
    $key_9d76 = { ca 04 [2] f8 26 [2] fe 13 [2] d0 13 [2] ef 0f }

  condition:
    any of them
}