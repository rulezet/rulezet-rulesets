rule TTP_XOR_WriteProcessMemory_3688 {
  strings:
    $key_3688 = { 61 fa [2] 53 d8 [2] 55 ed [2] 7b ed [2] 44 f1 }

  condition:
    any of them
}