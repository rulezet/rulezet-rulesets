rule TTP_XOR_WriteProcessMemory_8665 {
  strings:
    $key_8665 = { d1 17 [2] e3 35 [2] e5 00 [2] cb 00 [2] f4 1c }

  condition:
    any of them
}