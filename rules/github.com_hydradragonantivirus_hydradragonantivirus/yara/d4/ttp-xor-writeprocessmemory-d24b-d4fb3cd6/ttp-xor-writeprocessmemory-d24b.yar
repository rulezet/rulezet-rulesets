rule TTP_XOR_WriteProcessMemory_d24b {
  strings:
    $key_d24b = { 85 39 [2] b7 1b [2] b1 2e [2] 9f 2e [2] a0 32 }

  condition:
    any of them
}