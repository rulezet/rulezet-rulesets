rule TTP_XOR_WriteProcessMemory_7ac0 {
  strings:
    $key_7ac0 = { 2d b2 [2] 1f 90 [2] 19 a5 [2] 37 a5 [2] 08 b9 }

  condition:
    any of them
}