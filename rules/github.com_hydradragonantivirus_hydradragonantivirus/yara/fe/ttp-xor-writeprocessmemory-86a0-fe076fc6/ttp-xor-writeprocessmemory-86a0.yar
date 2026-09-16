rule TTP_XOR_WriteProcessMemory_86a0 {
  strings:
    $key_86a0 = { d1 d2 [2] e3 f0 [2] e5 c5 [2] cb c5 [2] f4 d9 }

  condition:
    any of them
}