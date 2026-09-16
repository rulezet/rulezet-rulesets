rule TTP_XOR_WriteProcessMemory_1ae5 {
  strings:
    $key_1ae5 = { 4d 97 [2] 7f b5 [2] 79 80 [2] 57 80 [2] 68 9c }

  condition:
    any of them
}