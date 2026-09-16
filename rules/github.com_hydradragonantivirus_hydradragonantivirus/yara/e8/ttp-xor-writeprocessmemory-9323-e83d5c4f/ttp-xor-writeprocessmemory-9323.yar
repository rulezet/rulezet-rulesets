rule TTP_XOR_WriteProcessMemory_9323 {
  strings:
    $key_9323 = { c4 51 [2] f6 73 [2] f0 46 [2] de 46 [2] e1 5a }

  condition:
    any of them
}