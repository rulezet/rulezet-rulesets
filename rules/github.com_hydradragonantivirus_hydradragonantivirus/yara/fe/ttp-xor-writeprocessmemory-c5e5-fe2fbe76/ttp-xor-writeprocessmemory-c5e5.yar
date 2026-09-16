rule TTP_XOR_WriteProcessMemory_c5e5 {
  strings:
    $key_c5e5 = { 92 97 [2] a0 b5 [2] a6 80 [2] 88 80 [2] b7 9c }

  condition:
    any of them
}