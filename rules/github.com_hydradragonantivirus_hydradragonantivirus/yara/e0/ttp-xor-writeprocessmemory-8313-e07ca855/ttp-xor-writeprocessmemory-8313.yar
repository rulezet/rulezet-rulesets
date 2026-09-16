rule TTP_XOR_WriteProcessMemory_8313 {
  strings:
    $key_8313 = { d4 61 [2] e6 43 [2] e0 76 [2] ce 76 [2] f1 6a }

  condition:
    any of them
}