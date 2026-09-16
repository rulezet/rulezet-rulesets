rule TTP_XOR_WriteProcessMemory_82f9 {
  strings:
    $key_82f9 = { d5 8b [2] e7 a9 [2] e1 9c [2] cf 9c [2] f0 80 }

  condition:
    any of them
}