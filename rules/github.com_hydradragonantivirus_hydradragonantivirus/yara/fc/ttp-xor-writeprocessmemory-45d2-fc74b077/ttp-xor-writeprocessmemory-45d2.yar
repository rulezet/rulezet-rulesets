rule TTP_XOR_WriteProcessMemory_45d2 {
  strings:
    $key_45d2 = { 12 a0 [2] 20 82 [2] 26 b7 [2] 08 b7 [2] 37 ab }

  condition:
    any of them
}