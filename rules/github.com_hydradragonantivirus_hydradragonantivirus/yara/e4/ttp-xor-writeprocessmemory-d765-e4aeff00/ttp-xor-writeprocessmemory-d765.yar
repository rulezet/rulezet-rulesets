rule TTP_XOR_WriteProcessMemory_d765 {
  strings:
    $key_d765 = { 80 17 [2] b2 35 [2] b4 00 [2] 9a 00 [2] a5 1c }

  condition:
    any of them
}