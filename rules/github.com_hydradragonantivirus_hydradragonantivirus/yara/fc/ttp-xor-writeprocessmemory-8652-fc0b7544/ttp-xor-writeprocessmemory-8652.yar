rule TTP_XOR_WriteProcessMemory_8652 {
  strings:
    $key_8652 = { d1 20 [2] e3 02 [2] e5 37 [2] cb 37 [2] f4 2b }

  condition:
    any of them
}