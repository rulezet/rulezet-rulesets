rule TTP_XOR_WriteProcessMemory_8649 {
  strings:
    $key_8649 = { d1 3b [2] e3 19 [2] e5 2c [2] cb 2c [2] f4 30 }

  condition:
    any of them
}