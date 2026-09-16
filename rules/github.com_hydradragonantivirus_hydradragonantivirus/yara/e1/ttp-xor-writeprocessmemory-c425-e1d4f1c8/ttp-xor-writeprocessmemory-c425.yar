rule TTP_XOR_WriteProcessMemory_c425 {
  strings:
    $key_c425 = { 93 57 [2] a1 75 [2] a7 40 [2] 89 40 [2] b6 5c }

  condition:
    any of them
}