rule TTP_XOR_WriteProcessMemory_92e6 {
  strings:
    $key_92e6 = { c5 94 [2] f7 b6 [2] f1 83 [2] df 83 [2] e0 9f }

  condition:
    any of them
}