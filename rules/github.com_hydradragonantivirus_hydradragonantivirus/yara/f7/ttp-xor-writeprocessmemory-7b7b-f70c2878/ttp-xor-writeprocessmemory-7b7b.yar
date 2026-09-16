rule TTP_XOR_WriteProcessMemory_7b7b {
  strings:
    $key_7b7b = { 2c 09 [2] 1e 2b [2] 18 1e [2] 36 1e [2] 09 02 }

  condition:
    any of them
}