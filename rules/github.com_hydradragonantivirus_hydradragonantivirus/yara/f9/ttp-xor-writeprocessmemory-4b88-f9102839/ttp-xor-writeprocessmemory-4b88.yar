rule TTP_XOR_WriteProcessMemory_4b88 {
  strings:
    $key_4b88 = { 1c fa [2] 2e d8 [2] 28 ed [2] 06 ed [2] 39 f1 }

  condition:
    any of them
}