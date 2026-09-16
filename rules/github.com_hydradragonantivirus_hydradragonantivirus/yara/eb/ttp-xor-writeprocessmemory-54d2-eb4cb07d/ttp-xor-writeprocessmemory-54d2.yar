rule TTP_XOR_WriteProcessMemory_54d2 {
  strings:
    $key_54d2 = { 03 a0 [2] 31 82 [2] 37 b7 [2] 19 b7 [2] 26 ab }

  condition:
    any of them
}