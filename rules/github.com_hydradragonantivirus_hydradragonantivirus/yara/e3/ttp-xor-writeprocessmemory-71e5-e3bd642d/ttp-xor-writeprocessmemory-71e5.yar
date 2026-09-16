rule TTP_XOR_WriteProcessMemory_71e5 {
  strings:
    $key_71e5 = { 26 97 [2] 14 b5 [2] 12 80 [2] 3c 80 [2] 03 9c }

  condition:
    any of them
}