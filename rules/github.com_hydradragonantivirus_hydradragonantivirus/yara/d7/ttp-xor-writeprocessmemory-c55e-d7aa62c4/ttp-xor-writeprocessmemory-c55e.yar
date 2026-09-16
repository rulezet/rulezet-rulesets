rule TTP_XOR_WriteProcessMemory_c55e {
  strings:
    $key_c55e = { 92 2c [2] a0 0e [2] a6 3b [2] 88 3b [2] b7 27 }

  condition:
    any of them
}