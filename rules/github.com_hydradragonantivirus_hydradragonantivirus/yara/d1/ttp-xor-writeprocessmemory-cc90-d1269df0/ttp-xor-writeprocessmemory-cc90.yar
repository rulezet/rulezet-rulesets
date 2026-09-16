rule TTP_XOR_WriteProcessMemory_cc90 {
  strings:
    $key_cc90 = { 9b e2 [2] a9 c0 [2] af f5 [2] 81 f5 [2] be e9 }

  condition:
    any of them
}