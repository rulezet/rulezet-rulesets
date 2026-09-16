rule TTP_XOR_WriteProcessMemory_c37b {
  strings:
    $key_c37b = { 94 09 [2] a6 2b [2] a0 1e [2] 8e 1e [2] b1 02 }

  condition:
    any of them
}