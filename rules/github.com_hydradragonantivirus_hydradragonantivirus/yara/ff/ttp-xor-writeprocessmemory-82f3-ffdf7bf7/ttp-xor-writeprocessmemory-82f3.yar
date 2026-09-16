rule TTP_XOR_WriteProcessMemory_82f3 {
  strings:
    $key_82f3 = { d5 81 [2] e7 a3 [2] e1 96 [2] cf 96 [2] f0 8a }

  condition:
    any of them
}