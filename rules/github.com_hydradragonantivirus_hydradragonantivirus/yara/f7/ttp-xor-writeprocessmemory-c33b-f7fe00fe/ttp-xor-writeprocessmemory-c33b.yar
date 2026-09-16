rule TTP_XOR_WriteProcessMemory_c33b {
  strings:
    $key_c33b = { 94 49 [2] a6 6b [2] a0 5e [2] 8e 5e [2] b1 42 }

  condition:
    any of them
}