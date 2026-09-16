rule TTP_XOR_WriteProcessMemory_5188 {
  strings:
    $key_5188 = { 06 fa [2] 34 d8 [2] 32 ed [2] 1c ed [2] 23 f1 }

  condition:
    any of them
}