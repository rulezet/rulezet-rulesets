rule TTP_XOR_WriteProcessMemory_85e9 {
  strings:
    $key_85e9 = { d2 9b [2] e0 b9 [2] e6 8c [2] c8 8c [2] f7 90 }

  condition:
    any of them
}