rule TTP_XOR_WriteProcessMemory_8660 {
  strings:
    $key_8660 = { d1 12 [2] e3 30 [2] e5 05 [2] cb 05 [2] f4 19 }

  condition:
    any of them
}