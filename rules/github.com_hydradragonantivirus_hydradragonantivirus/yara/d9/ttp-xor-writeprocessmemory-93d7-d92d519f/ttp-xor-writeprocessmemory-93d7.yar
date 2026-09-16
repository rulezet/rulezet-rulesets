rule TTP_XOR_WriteProcessMemory_93d7 {
  strings:
    $key_93d7 = { c4 a5 [2] f6 87 [2] f0 b2 [2] de b2 [2] e1 ae }

  condition:
    any of them
}