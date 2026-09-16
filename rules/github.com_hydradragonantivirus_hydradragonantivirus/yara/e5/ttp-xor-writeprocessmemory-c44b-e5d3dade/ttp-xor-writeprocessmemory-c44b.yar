rule TTP_XOR_WriteProcessMemory_c44b {
  strings:
    $key_c44b = { 93 39 [2] a1 1b [2] a7 2e [2] 89 2e [2] b6 32 }

  condition:
    any of them
}