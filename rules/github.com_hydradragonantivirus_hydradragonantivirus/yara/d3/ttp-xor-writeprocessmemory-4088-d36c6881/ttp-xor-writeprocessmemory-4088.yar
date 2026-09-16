rule TTP_XOR_WriteProcessMemory_4088 {
  strings:
    $key_4088 = { 17 fa [2] 25 d8 [2] 23 ed [2] 0d ed [2] 32 f1 }

  condition:
    any of them
}