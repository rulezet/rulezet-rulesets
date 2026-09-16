rule TTP_XOR_WriteProcessMemory_91b4 {
  strings:
    $key_91b4 = { c6 c6 [2] f4 e4 [2] f2 d1 [2] dc d1 [2] e3 cd }

  condition:
    any of them
}