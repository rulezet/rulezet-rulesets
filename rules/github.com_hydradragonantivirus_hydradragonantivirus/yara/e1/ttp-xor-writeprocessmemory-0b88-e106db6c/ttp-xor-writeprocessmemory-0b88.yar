rule TTP_XOR_WriteProcessMemory_0b88 {
  strings:
    $key_0b88 = { 5c fa [2] 6e d8 [2] 68 ed [2] 46 ed [2] 79 f1 }

  condition:
    any of them
}