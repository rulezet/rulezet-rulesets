rule TTP_XOR_WriteProcessMemory_7f88 {
  strings:
    $key_7f88 = { 28 fa [2] 1a d8 [2] 1c ed [2] 32 ed [2] 0d f1 }

  condition:
    any of them
}