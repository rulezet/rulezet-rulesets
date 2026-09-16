rule TTP_XOR_WriteProcessMemory_c13b {
  strings:
    $key_c13b = { 96 49 [2] a4 6b [2] a2 5e [2] 8c 5e [2] b3 42 }

  condition:
    any of them
}