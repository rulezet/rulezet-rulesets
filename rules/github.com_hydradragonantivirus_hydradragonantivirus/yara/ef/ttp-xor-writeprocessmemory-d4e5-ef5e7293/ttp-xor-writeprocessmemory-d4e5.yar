rule TTP_XOR_WriteProcessMemory_d4e5 {
  strings:
    $key_d4e5 = { 83 97 [2] b1 b5 [2] b7 80 [2] 99 80 [2] a6 9c }

  condition:
    any of them
}