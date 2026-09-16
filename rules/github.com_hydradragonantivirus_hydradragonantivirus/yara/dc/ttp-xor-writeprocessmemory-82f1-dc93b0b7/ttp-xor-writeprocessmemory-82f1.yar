rule TTP_XOR_WriteProcessMemory_82f1 {
  strings:
    $key_82f1 = { d5 83 [2] e7 a1 [2] e1 94 [2] cf 94 [2] f0 88 }

  condition:
    any of them
}