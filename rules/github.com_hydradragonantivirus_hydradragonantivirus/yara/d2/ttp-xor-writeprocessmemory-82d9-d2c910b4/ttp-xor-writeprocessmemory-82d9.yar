rule TTP_XOR_WriteProcessMemory_82d9 {
  strings:
    $key_82d9 = { d5 ab [2] e7 89 [2] e1 bc [2] cf bc [2] f0 a0 }

  condition:
    any of them
}