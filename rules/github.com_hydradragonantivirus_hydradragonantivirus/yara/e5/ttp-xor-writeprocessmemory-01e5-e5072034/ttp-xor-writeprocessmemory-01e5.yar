rule TTP_XOR_WriteProcessMemory_01e5 {
  strings:
    $key_01e5 = { 56 97 [2] 64 b5 [2] 62 80 [2] 4c 80 [2] 73 9c }

  condition:
    any of them
}