rule TTP_XOR_WriteProcessMemory_5788 {
  strings:
    $key_5788 = { 00 fa [2] 32 d8 [2] 34 ed [2] 1a ed [2] 25 f1 }

  condition:
    any of them
}