rule TTP_XOR_WriteProcessMemory_f688 {
  strings:
    $key_f688 = { a1 fa [2] 93 d8 [2] 95 ed [2] bb ed [2] 84 f1 }

  condition:
    any of them
}