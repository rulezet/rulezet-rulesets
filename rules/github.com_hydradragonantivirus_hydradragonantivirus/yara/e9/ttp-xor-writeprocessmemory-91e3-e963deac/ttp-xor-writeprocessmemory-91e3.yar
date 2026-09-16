rule TTP_XOR_WriteProcessMemory_91e3 {
  strings:
    $key_91e3 = { c6 91 [2] f4 b3 [2] f2 86 [2] dc 86 [2] e3 9a }

  condition:
    any of them
}