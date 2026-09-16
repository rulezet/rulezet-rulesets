rule TTP_XOR_WriteProcessMemory_85f1 {
  strings:
    $key_85f1 = { d2 83 [2] e0 a1 [2] e6 94 [2] c8 94 [2] f7 88 }

  condition:
    any of them
}