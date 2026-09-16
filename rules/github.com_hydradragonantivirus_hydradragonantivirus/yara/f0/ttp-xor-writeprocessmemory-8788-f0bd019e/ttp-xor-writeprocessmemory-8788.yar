rule TTP_XOR_WriteProcessMemory_8788 {
  strings:
    $key_8788 = { d0 fa [2] e2 d8 [2] e4 ed [2] ca ed [2] f5 f1 }

  condition:
    any of them
}