rule TTP_XOR_WriteProcessMemory_5688 {
  strings:
    $key_5688 = { 01 fa [2] 33 d8 [2] 35 ed [2] 1b ed [2] 24 f1 }

  condition:
    any of them
}