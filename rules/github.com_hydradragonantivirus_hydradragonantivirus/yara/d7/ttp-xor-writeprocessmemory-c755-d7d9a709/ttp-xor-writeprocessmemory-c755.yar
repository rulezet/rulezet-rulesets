rule TTP_XOR_WriteProcessMemory_c755 {
  strings:
    $key_c755 = { 90 27 [2] a2 05 [2] a4 30 [2] 8a 30 [2] b5 2c }

  condition:
    any of them
}