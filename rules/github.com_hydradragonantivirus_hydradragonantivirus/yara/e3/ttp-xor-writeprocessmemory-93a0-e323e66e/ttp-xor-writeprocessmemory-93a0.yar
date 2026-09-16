rule TTP_XOR_WriteProcessMemory_93a0 {
  strings:
    $key_93a0 = { c4 d2 [2] f6 f0 [2] f0 c5 [2] de c5 [2] e1 d9 }

  condition:
    any of them
}