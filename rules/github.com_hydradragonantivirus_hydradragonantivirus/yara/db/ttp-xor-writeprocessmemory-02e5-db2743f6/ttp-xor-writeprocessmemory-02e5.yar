rule TTP_XOR_WriteProcessMemory_02e5 {
  strings:
    $key_02e5 = { 55 97 [2] 67 b5 [2] 61 80 [2] 4f 80 [2] 70 9c }

  condition:
    any of them
}