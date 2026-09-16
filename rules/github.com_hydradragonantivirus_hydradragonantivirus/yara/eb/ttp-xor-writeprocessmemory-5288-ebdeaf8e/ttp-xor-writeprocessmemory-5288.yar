rule TTP_XOR_WriteProcessMemory_5288 {
  strings:
    $key_5288 = { 05 fa [2] 37 d8 [2] 31 ed [2] 1f ed [2] 20 f1 }

  condition:
    any of them
}