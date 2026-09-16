rule TTP_XOR_WriteProcessMemory_c1e5 {
  strings:
    $key_c1e5 = { 96 97 [2] a4 b5 [2] a2 80 [2] 8c 80 [2] b3 9c }

  condition:
    any of them
}