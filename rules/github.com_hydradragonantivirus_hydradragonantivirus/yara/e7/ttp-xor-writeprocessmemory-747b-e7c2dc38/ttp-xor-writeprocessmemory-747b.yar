rule TTP_XOR_WriteProcessMemory_747b {
  strings:
    $key_747b = { 23 09 [2] 11 2b [2] 17 1e [2] 39 1e [2] 06 02 }

  condition:
    any of them
}