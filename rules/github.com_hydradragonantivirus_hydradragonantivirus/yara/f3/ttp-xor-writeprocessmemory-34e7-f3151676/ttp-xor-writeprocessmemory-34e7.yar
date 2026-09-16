rule TTP_XOR_WriteProcessMemory_34e7 {
  strings:
    $key_34e7 = { 63 95 [2] 51 b7 [2] 57 82 [2] 79 82 [2] 46 9e }

  condition:
    any of them
}