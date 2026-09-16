rule TTP_XOR_WriteProcessMemory_91f0 {
  strings:
    $key_91f0 = { c6 82 [2] f4 a0 [2] f2 95 [2] dc 95 [2] e3 89 }

  condition:
    any of them
}