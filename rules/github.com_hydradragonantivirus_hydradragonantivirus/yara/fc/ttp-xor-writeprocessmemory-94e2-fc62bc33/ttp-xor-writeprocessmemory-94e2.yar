rule TTP_XOR_WriteProcessMemory_94e2 {
  strings:
    $key_94e2 = { c3 90 [2] f1 b2 [2] f7 87 [2] d9 87 [2] e6 9b }

  condition:
    any of them
}