rule TTP_XOR_WriteProcessMemory_c10b {
  strings:
    $key_c10b = { 96 79 [2] a4 5b [2] a2 6e [2] 8c 6e [2] b3 72 }

  condition:
    any of them
}