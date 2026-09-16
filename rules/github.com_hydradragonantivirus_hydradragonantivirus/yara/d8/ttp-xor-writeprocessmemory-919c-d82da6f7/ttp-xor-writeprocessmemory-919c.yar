rule TTP_XOR_WriteProcessMemory_919c {
  strings:
    $key_919c = { c6 ee [2] f4 cc [2] f2 f9 [2] dc f9 [2] e3 e5 }

  condition:
    any of them
}