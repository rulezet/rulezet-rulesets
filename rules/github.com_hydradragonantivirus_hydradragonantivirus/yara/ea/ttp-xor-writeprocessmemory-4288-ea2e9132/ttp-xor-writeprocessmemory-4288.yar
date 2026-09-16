rule TTP_XOR_WriteProcessMemory_4288 {
  strings:
    $key_4288 = { 15 fa [2] 27 d8 [2] 21 ed [2] 0f ed [2] 30 f1 }

  condition:
    any of them
}