rule TTP_XOR_WriteProcessMemory_4188 {
  strings:
    $key_4188 = { 16 fa [2] 24 d8 [2] 22 ed [2] 0c ed [2] 33 f1 }

  condition:
    any of them
}