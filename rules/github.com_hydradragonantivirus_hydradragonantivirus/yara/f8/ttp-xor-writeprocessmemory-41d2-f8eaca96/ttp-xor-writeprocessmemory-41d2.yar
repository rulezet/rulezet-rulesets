rule TTP_XOR_WriteProcessMemory_41d2 {
  strings:
    $key_41d2 = { 16 a0 [2] 24 82 [2] 22 b7 [2] 0c b7 [2] 33 ab }

  condition:
    any of them
}