rule TTP_XOR_WriteProcessMemory_c465 {
  strings:
    $key_c465 = { 93 17 [2] a1 35 [2] a7 00 [2] 89 00 [2] b6 1c }

  condition:
    any of them
}