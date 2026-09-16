rule TTP_XOR_WriteProcessMemory_c735 {
  strings:
    $key_c735 = { 90 47 [2] a2 65 [2] a4 50 [2] 8a 50 [2] b5 4c }

  condition:
    any of them
}