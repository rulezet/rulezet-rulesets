rule TTP_XOR_WriteProcessMemory_6188 {
  strings:
    $key_6188 = { 36 fa [2] 04 d8 [2] 02 ed [2] 2c ed [2] 13 f1 }

  condition:
    any of them
}