rule TTP_XOR_WriteProcessMemory_1ac0 {
  strings:
    $key_1ac0 = { 4d b2 [2] 7f 90 [2] 79 a5 [2] 57 a5 [2] 68 b9 }

  condition:
    any of them
}