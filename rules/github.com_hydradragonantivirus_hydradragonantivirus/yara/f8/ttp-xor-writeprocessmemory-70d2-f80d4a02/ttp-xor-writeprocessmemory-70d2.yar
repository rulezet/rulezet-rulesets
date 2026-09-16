rule TTP_XOR_WriteProcessMemory_70d2 {
  strings:
    $key_70d2 = { 27 a0 [2] 15 82 [2] 13 b7 [2] 3d b7 [2] 02 ab }

  condition:
    any of them
}