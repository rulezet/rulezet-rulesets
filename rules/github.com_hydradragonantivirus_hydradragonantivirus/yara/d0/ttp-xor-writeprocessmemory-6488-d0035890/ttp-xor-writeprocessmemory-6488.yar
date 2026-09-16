rule TTP_XOR_WriteProcessMemory_6488 {
  strings:
    $key_6488 = { 33 fa [2] 01 d8 [2] 07 ed [2] 29 ed [2] 16 f1 }

  condition:
    any of them
}