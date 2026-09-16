rule TTP_XOR_WriteProcessMemory_8604 {
  strings:
    $key_8604 = { d1 76 [2] e3 54 [2] e5 61 [2] cb 61 [2] f4 7d }

  condition:
    any of them
}