rule TTP_XOR_WriteProcessMemory_7c7b {
  strings:
    $key_7c7b = { 2b 09 [2] 19 2b [2] 1f 1e [2] 31 1e [2] 0e 02 }

  condition:
    any of them
}