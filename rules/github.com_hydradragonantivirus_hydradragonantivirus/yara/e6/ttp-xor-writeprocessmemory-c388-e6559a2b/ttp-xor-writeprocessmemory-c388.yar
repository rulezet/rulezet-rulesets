rule TTP_XOR_WriteProcessMemory_c388 {
  strings:
    $key_c388 = { 94 fa [2] a6 d8 [2] a0 ed [2] 8e ed [2] b1 f1 }

  condition:
    any of them
}