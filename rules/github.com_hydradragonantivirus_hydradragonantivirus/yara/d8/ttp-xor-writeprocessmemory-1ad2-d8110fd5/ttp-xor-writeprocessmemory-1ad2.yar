rule TTP_XOR_WriteProcessMemory_1ad2 {
  strings:
    $key_1ad2 = { 4d a0 [2] 7f 82 [2] 79 b7 [2] 57 b7 [2] 68 ab }

  condition:
    any of them
}