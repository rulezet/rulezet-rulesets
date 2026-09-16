rule TTP_XOR_WriteProcessMemory_86e0 {
  strings:
    $key_86e0 = { d1 92 [2] e3 b0 [2] e5 85 [2] cb 85 [2] f4 99 }

  condition:
    any of them
}