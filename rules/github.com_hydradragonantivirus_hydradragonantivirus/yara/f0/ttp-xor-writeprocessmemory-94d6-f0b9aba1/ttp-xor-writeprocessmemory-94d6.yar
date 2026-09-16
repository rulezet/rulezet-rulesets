rule TTP_XOR_WriteProcessMemory_94d6 {
  strings:
    $key_94d6 = { c3 a4 [2] f1 86 [2] f7 b3 [2] d9 b3 [2] e6 af }

  condition:
    any of them
}