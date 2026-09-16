rule TTP_XOR_WriteProcessMemory_c3e5 {
  strings:
    $key_c3e5 = { 94 97 [2] a6 b5 [2] a0 80 [2] 8e 80 [2] b1 9c }

  condition:
    any of them
}