rule TTP_XOR_WriteProcessMemory_91d2 {
  strings:
    $key_91d2 = { c6 a0 [2] f4 82 [2] f2 b7 [2] dc b7 [2] e3 ab }

  condition:
    any of them
}