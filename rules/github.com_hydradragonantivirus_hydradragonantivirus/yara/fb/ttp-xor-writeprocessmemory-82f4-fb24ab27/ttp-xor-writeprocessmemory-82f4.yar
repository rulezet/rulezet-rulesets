rule TTP_XOR_WriteProcessMemory_82f4 {
  strings:
    $key_82f4 = { d5 86 [2] e7 a4 [2] e1 91 [2] cf 91 [2] f0 8d }

  condition:
    any of them
}