rule TTP_XOR_WriteProcessMemory_ac81 {
  strings:
    $key_ac81 = { fb f3 [2] c9 d1 [2] cf e4 [2] e1 e4 [2] de f8 }

  condition:
    any of them
}