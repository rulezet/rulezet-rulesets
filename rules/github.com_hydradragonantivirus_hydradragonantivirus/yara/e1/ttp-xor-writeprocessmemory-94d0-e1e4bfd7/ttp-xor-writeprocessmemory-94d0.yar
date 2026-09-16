rule TTP_XOR_WriteProcessMemory_94d0 {
  strings:
    $key_94d0 = { c3 a2 [2] f1 80 [2] f7 b5 [2] d9 b5 [2] e6 a9 }

  condition:
    any of them
}