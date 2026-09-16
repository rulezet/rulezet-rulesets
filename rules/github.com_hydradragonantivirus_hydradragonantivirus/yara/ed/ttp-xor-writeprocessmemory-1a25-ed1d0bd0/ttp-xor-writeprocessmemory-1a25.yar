rule TTP_XOR_WriteProcessMemory_1a25 {
  strings:
    $key_1a25 = { 4d 57 [2] 7f 75 [2] 79 40 [2] 57 40 [2] 68 5c }

  condition:
    any of them
}