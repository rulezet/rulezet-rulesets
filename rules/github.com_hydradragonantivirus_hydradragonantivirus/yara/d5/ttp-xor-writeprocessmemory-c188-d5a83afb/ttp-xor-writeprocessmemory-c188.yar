rule TTP_XOR_WriteProcessMemory_c188 {
  strings:
    $key_c188 = { 96 fa [2] a4 d8 [2] a2 ed [2] 8c ed [2] b3 f1 }

  condition:
    any of them
}