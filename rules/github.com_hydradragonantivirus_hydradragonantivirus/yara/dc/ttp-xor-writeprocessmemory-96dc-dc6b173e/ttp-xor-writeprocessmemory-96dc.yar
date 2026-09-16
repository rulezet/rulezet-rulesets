rule TTP_XOR_WriteProcessMemory_96dc {
  strings:
    $key_96dc = { c1 ae [2] f3 8c [2] f5 b9 [2] db b9 [2] e4 a5 }

  condition:
    any of them
}