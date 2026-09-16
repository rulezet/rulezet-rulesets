rule TTP_XOR_WriteProcessMemory_4ac0 {
  strings:
    $key_4ac0 = { 1d b2 [2] 2f 90 [2] 29 a5 [2] 07 a5 [2] 38 b9 }

  condition:
    any of them
}