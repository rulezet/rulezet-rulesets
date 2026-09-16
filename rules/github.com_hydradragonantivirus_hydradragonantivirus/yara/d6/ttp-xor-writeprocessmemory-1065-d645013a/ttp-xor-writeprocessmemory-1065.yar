rule TTP_XOR_WriteProcessMemory_1065 {
  strings:
    $key_1065 = { 47 17 [2] 75 35 [2] 73 00 [2] 5d 00 [2] 62 1c }

  condition:
    any of them
}