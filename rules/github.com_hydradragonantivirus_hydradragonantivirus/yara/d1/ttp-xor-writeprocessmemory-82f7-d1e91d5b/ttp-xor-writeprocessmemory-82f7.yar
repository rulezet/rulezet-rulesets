rule TTP_XOR_WriteProcessMemory_82f7 {
  strings:
    $key_82f7 = { d5 85 [2] e7 a7 [2] e1 92 [2] cf 92 [2] f0 8e }

  condition:
    any of them
}