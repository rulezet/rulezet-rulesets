rule TTP_XOR_WriteProcessMemory_e2d2 {
  strings:
    $key_e2d2 = { b5 a0 [2] 87 82 [2] 81 b7 [2] af b7 [2] 90 ab }

  condition:
    any of them
}