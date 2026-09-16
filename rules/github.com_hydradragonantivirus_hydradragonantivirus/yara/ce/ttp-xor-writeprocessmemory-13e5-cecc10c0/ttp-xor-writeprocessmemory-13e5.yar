rule TTP_XOR_WriteProcessMemory_13e5 {
  strings:
    $key_13e5 = { 44 97 [2] 76 b5 [2] 70 80 [2] 5e 80 [2] 61 9c }

  condition:
    any of them
}