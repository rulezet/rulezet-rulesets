rule TTP_XOR_WriteProcessMemory_93d1 {
  strings:
    $key_93d1 = { c4 a3 [2] f6 81 [2] f0 b4 [2] de b4 [2] e1 a8 }

  condition:
    any of them
}