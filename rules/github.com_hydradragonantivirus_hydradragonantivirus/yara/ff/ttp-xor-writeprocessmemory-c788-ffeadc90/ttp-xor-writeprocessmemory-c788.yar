rule TTP_XOR_WriteProcessMemory_c788 {
  strings:
    $key_c788 = { 90 fa [2] a2 d8 [2] a4 ed [2] 8a ed [2] b5 f1 }

  condition:
    any of them
}