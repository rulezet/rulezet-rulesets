rule TTP_XOR_WriteProcessMemory_92e0 {
  strings:
    $key_92e0 = { c5 92 [2] f7 b0 [2] f1 85 [2] df 85 [2] e0 99 }

  condition:
    any of them
}