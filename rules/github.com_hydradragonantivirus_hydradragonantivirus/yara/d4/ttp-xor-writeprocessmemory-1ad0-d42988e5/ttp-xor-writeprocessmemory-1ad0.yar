rule TTP_XOR_WriteProcessMemory_1ad0 {
  strings:
    $key_1ad0 = { 4d a2 [2] 7f 80 [2] 79 b5 [2] 57 b5 [2] 68 a9 }

  condition:
    any of them
}