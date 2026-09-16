rule TTP_XOR_WriteProcessMemory_94a2 {
  strings:
    $key_94a2 = { c3 d0 [2] f1 f2 [2] f7 c7 [2] d9 c7 [2] e6 db }

  condition:
    any of them
}