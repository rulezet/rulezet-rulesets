rule TTP_XOR_WriteProcessMemory_1af5 {
  strings:
    $key_1af5 = { 4d 87 [2] 7f a5 [2] 79 90 [2] 57 90 [2] 68 8c }

  condition:
    any of them
}