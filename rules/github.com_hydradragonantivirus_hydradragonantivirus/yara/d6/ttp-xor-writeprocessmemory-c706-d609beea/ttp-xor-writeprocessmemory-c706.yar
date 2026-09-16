rule TTP_XOR_WriteProcessMemory_c706 {
  strings:
    $key_c706 = { 90 74 [2] a2 56 [2] a4 63 [2] 8a 63 [2] b5 7f }

  condition:
    any of them
}