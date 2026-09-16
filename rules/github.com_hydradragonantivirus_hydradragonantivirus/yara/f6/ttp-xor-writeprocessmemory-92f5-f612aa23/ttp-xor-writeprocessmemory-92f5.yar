rule TTP_XOR_WriteProcessMemory_92f5 {
  strings:
    $key_92f5 = { c5 87 [2] f7 a5 [2] f1 90 [2] df 90 [2] e0 8c }

  condition:
    any of them
}