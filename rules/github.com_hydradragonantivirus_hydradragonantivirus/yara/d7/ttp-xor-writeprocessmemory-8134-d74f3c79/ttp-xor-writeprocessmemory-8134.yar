rule TTP_XOR_WriteProcessMemory_8134 {
  strings:
    $key_8134 = { d6 46 [2] e4 64 [2] e2 51 [2] cc 51 [2] f3 4d }

  condition:
    any of them
}