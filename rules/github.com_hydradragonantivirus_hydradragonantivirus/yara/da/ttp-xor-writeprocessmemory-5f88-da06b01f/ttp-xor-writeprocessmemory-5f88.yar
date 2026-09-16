rule TTP_XOR_WriteProcessMemory_5f88 {
  strings:
    $key_5f88 = { 08 fa [2] 3a d8 [2] 3c ed [2] 12 ed [2] 2d f1 }

  condition:
    any of them
}