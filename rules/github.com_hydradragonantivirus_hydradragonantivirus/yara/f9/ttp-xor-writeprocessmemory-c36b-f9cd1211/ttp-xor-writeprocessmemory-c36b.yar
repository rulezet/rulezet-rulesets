rule TTP_XOR_WriteProcessMemory_c36b {
  strings:
    $key_c36b = { 94 19 [2] a6 3b [2] a0 0e [2] 8e 0e [2] b1 12 }

  condition:
    any of them
}