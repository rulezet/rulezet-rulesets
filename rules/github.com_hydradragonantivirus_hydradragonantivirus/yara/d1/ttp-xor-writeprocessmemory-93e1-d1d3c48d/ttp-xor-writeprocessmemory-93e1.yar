rule TTP_XOR_WriteProcessMemory_93e1 {
  strings:
    $key_93e1 = { c4 93 [2] f6 b1 [2] f0 84 [2] de 84 [2] e1 98 }

  condition:
    any of them
}