rule TTP_XOR_WriteProcessMemory_2bd2 {
  strings:
    $key_2bd2 = { 7c a0 [2] 4e 82 [2] 48 b7 [2] 66 b7 [2] 59 ab }

  condition:
    any of them
}