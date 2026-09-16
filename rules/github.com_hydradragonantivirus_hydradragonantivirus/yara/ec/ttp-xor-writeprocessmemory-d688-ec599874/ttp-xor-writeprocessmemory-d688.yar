rule TTP_XOR_WriteProcessMemory_d688 {
  strings:
    $key_d688 = { 81 fa [2] b3 d8 [2] b5 ed [2] 9b ed [2] a4 f1 }

  condition:
    any of them
}