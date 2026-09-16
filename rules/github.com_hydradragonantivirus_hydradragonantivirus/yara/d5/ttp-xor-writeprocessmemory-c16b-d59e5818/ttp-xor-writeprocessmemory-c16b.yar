rule TTP_XOR_WriteProcessMemory_c16b {
  strings:
    $key_c16b = { 96 19 [2] a4 3b [2] a2 0e [2] 8c 0e [2] b3 12 }

  condition:
    any of them
}