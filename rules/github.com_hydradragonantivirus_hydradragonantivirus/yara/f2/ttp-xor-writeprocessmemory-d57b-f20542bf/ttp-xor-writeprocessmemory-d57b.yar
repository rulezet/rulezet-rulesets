rule TTP_XOR_WriteProcessMemory_d57b {
  strings:
    $key_d57b = { 82 09 [2] b0 2b [2] b6 1e [2] 98 1e [2] a7 02 }

  condition:
    any of them
}