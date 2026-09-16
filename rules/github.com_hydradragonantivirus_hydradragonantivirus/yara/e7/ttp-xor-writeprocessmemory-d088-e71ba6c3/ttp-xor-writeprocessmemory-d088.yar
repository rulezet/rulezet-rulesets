rule TTP_XOR_WriteProcessMemory_d088 {
  strings:
    $key_d088 = { 87 fa [2] b5 d8 [2] b3 ed [2] 9d ed [2] a2 f1 }

  condition:
    any of them
}