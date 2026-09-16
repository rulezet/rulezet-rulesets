rule TTP_XOR_WriteProcessMemory_3188 {
  strings:
    $key_3188 = { 66 fa [2] 54 d8 [2] 52 ed [2] 7c ed [2] 43 f1 }

  condition:
    any of them
}