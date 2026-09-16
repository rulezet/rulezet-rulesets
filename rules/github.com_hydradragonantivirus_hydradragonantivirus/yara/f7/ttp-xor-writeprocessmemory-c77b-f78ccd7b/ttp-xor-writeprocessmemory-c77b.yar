rule TTP_XOR_WriteProcessMemory_c77b {
  strings:
    $key_c77b = { 90 09 [2] a2 2b [2] a4 1e [2] 8a 1e [2] b5 02 }

  condition:
    any of them
}