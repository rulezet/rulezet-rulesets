rule TTP_XOR_WriteProcessMemory_f588 {
  strings:
    $key_f588 = { a2 fa [2] 90 d8 [2] 96 ed [2] b8 ed [2] 87 f1 }

  condition:
    any of them
}