rule TTP_XOR_WriteProcessMemory_7c88 {
  strings:
    $key_7c88 = { 2b fa [2] 19 d8 [2] 1f ed [2] 31 ed [2] 0e f1 }

  condition:
    any of them
}