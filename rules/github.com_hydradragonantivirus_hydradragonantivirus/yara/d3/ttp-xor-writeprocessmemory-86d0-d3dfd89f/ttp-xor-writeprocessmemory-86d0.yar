rule TTP_XOR_WriteProcessMemory_86d0 {
  strings:
    $key_86d0 = { d1 a2 [2] e3 80 [2] e5 b5 [2] cb b5 [2] f4 a9 }

  condition:
    any of them
}