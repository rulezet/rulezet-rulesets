rule TTP_XOR_WriteProcessMemory_8691 {
  strings:
    $key_8691 = { d1 e3 [2] e3 c1 [2] e5 f4 [2] cb f4 [2] f4 e8 }

  condition:
    any of them
}