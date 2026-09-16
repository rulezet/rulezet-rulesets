rule TTP_XOR_WriteProcessMemory_94a4 {
  strings:
    $key_94a4 = { c3 d6 [2] f1 f4 [2] f7 c1 [2] d9 c1 [2] e6 dd }

  condition:
    any of them
}