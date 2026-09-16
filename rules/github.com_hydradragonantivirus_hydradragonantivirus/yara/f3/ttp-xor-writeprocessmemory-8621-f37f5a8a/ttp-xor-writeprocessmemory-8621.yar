rule TTP_XOR_WriteProcessMemory_8621 {
  strings:
    $key_8621 = { d1 53 [2] e3 71 [2] e5 44 [2] cb 44 [2] f4 58 }

  condition:
    any of them
}