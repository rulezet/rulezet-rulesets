rule TTP_XOR_WriteProcessMemory_1af1 {
  strings:
    $key_1af1 = { 4d 83 [2] 7f a1 [2] 79 94 [2] 57 94 [2] 68 88 }

  condition:
    any of them
}