rule TTP_XOR_WriteProcessMemory_1a88 {
  strings:
    $key_1a88 = { 4d fa [2] 7f d8 [2] 79 ed [2] 57 ed [2] 68 f1 }

  condition:
    any of them
}