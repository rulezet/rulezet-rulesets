rule TTP_XOR_WriteProcessMemory_31d2 {
  strings:
    $key_31d2 = { 66 a0 [2] 54 82 [2] 52 b7 [2] 7c b7 [2] 43 ab }

  condition:
    any of them
}