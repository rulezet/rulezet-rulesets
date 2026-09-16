rule TTP_XOR_WriteProcessMemory_9dd5 {
  strings:
    $key_9dd5 = { ca a7 [2] f8 85 [2] fe b0 [2] d0 b0 [2] ef ac }

  condition:
    any of them
}