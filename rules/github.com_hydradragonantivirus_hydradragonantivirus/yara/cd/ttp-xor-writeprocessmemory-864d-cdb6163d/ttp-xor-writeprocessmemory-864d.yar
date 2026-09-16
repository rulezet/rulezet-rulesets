rule TTP_XOR_WriteProcessMemory_864d {
  strings:
    $key_864d = { d1 3f [2] e3 1d [2] e5 28 [2] cb 28 [2] f4 34 }

  condition:
    any of them
}