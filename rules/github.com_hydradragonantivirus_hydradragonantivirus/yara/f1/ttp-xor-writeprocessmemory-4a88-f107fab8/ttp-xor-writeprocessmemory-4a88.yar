rule TTP_XOR_WriteProcessMemory_4a88 {
  strings:
    $key_4a88 = { 1d fa [2] 2f d8 [2] 29 ed [2] 07 ed [2] 38 f1 }

  condition:
    any of them
}