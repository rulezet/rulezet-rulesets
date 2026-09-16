rule TTP_XOR_WriteProcessMemory_27d2 {
  strings:
    $key_27d2 = { 70 a0 [2] 42 82 [2] 44 b7 [2] 6a b7 [2] 55 ab }

  condition:
    any of them
}