rule TTP_XOR_WriteProcessMemory_0f88 {
  strings:
    $key_0f88 = { 58 fa [2] 6a d8 [2] 6c ed [2] 42 ed [2] 7d f1 }

  condition:
    any of them
}