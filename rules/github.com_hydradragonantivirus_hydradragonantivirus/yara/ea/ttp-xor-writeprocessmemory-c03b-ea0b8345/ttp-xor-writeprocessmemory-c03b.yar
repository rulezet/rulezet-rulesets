rule TTP_XOR_WriteProcessMemory_c03b {
  strings:
    $key_c03b = { 97 49 [2] a5 6b [2] a3 5e [2] 8d 5e [2] b2 42 }

  condition:
    any of them
}