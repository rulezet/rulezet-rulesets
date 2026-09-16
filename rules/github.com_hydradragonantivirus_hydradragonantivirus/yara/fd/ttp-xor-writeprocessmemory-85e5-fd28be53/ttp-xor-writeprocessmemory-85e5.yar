rule TTP_XOR_WriteProcessMemory_85e5 {
  strings:
    $key_85e5 = { d2 97 [2] e0 b5 [2] e6 80 [2] c8 80 [2] f7 9c }

  condition:
    any of them
}