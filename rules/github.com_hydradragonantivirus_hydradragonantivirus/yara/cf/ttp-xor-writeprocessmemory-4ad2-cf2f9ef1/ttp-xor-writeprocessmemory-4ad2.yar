rule TTP_XOR_WriteProcessMemory_4ad2 {
  strings:
    $key_4ad2 = { 1d a0 [2] 2f 82 [2] 29 b7 [2] 07 b7 [2] 38 ab }

  condition:
    any of them
}