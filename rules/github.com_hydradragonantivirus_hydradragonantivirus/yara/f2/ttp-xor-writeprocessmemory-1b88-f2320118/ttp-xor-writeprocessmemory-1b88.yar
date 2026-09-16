rule TTP_XOR_WriteProcessMemory_1b88 {
  strings:
    $key_1b88 = { 4c fa [2] 7e d8 [2] 78 ed [2] 56 ed [2] 69 f1 }

  condition:
    any of them
}