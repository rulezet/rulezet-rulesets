rule TTP_XOR_WriteProcessMemory_93c1 {
  strings:
    $key_93c1 = { c4 b3 [2] f6 91 [2] f0 a4 [2] de a4 [2] e1 b8 }

  condition:
    any of them
}