rule TTP_XOR_WriteProcessMemory_6b7b {
  strings:
    $key_6b7b = { 3c 09 [2] 0e 2b [2] 08 1e [2] 26 1e [2] 19 02 }

  condition:
    any of them
}