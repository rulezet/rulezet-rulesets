rule TTP_XOR_WriteProcessMemory_24d2 {
  strings:
    $key_24d2 = { 73 a0 [2] 41 82 [2] 47 b7 [2] 69 b7 [2] 56 ab }

  condition:
    any of them
}