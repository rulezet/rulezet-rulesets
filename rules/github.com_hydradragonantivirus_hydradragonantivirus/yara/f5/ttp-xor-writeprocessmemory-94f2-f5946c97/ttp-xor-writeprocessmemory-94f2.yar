rule TTP_XOR_WriteProcessMemory_94f2 {
  strings:
    $key_94f2 = { c3 80 [2] f1 a2 [2] f7 97 [2] d9 97 [2] e6 8b }

  condition:
    any of them
}