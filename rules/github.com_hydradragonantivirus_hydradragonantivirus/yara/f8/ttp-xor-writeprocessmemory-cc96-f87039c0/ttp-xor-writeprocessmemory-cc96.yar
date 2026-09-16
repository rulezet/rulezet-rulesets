rule TTP_XOR_WriteProcessMemory_cc96 {
  strings:
    $key_cc96 = { 9b e4 [2] a9 c6 [2] af f3 [2] 81 f3 [2] be ef }

  condition:
    any of them
}