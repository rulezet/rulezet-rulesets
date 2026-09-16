rule TTP_XOR_WriteProcessMemory_91e9 {
  strings:
    $key_91e9 = { c6 9b [2] f4 b9 [2] f2 8c [2] dc 8c [2] e3 90 }

  condition:
    any of them
}