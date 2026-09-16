rule TTP_XOR_WriteProcessMemory_c56b {
  strings:
    $key_c56b = { 92 19 [2] a0 3b [2] a6 0e [2] 88 0e [2] b7 12 }

  condition:
    any of them
}