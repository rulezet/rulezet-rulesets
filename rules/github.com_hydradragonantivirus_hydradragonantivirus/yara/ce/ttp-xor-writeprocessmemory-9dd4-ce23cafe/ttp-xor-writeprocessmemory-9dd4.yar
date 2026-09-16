rule TTP_XOR_WriteProcessMemory_9dd4 {
  strings:
    $key_9dd4 = { ca a6 [2] f8 84 [2] fe b1 [2] d0 b1 [2] ef ad }

  condition:
    any of them
}