rule TTP_XOR_WriteProcessMemory_6788 {
  strings:
    $key_6788 = { 30 fa [2] 02 d8 [2] 04 ed [2] 2a ed [2] 15 f1 }

  condition:
    any of them
}