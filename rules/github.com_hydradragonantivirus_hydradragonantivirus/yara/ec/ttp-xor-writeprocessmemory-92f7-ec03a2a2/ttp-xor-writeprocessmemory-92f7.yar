rule TTP_XOR_WriteProcessMemory_92f7 {
  strings:
    $key_92f7 = { c5 85 [2] f7 a7 [2] f1 92 [2] df 92 [2] e0 8e }

  condition:
    any of them
}