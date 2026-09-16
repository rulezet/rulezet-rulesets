rule TTP_XOR_WriteProcessMemory_7588 {
  strings:
    $key_7588 = { 22 fa [2] 10 d8 [2] 16 ed [2] 38 ed [2] 07 f1 }

  condition:
    any of them
}