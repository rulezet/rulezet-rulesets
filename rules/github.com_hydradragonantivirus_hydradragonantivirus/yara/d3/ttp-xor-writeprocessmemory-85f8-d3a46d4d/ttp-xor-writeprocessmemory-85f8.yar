rule TTP_XOR_WriteProcessMemory_85f8 {
  strings:
    $key_85f8 = { d2 8a [2] e0 a8 [2] e6 9d [2] c8 9d [2] f7 81 }

  condition:
    any of them
}