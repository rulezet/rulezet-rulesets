rule TTP_XOR_WriteProcessMemory_67e5 {
  strings:
    $key_67e5 = { 30 97 [2] 02 b5 [2] 04 80 [2] 2a 80 [2] 15 9c }

  condition:
    any of them
}