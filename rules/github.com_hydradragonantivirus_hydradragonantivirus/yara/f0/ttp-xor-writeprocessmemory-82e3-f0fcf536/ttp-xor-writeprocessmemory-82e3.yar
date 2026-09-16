rule TTP_XOR_WriteProcessMemory_82e3 {
  strings:
    $key_82e3 = { d5 91 [2] e7 b3 [2] e1 86 [2] cf 86 [2] f0 9a }

  condition:
    any of them
}