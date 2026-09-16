rule TTP_XOR_WriteProcessMemory_c37e {
  strings:
    $key_c37e = { 94 0c [2] a6 2e [2] a0 1b [2] 8e 1b [2] b1 07 }

  condition:
    any of them
}