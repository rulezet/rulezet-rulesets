rule TTP_XOR_WriteProcessMemory_9088 {
  strings:
    $key_9088 = { c7 fa [2] f5 d8 [2] f3 ed [2] dd ed [2] e2 f1 }

  condition:
    any of them
}