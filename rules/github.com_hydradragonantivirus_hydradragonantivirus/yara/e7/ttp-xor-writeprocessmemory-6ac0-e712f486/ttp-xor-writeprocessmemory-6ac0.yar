rule TTP_XOR_WriteProcessMemory_6ac0 {
  strings:
    $key_6ac0 = { 3d b2 [2] 0f 90 [2] 09 a5 [2] 27 a5 [2] 18 b9 }

  condition:
    any of them
}