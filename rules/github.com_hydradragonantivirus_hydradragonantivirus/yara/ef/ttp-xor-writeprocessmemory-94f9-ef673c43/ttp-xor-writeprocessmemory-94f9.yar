rule TTP_XOR_WriteProcessMemory_94f9 {
  strings:
    $key_94f9 = { c3 8b [2] f1 a9 [2] f7 9c [2] d9 9c [2] e6 80 }

  condition:
    any of them
}