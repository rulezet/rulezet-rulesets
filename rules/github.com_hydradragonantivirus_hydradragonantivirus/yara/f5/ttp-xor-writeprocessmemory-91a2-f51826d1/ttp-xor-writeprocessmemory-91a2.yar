rule TTP_XOR_WriteProcessMemory_91a2 {
  strings:
    $key_91a2 = { c6 d0 [2] f4 f2 [2] f2 c7 [2] dc c7 [2] e3 db }

  condition:
    any of them
}