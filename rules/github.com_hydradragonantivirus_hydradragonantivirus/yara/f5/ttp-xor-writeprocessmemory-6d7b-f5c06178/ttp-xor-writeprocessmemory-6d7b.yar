rule TTP_XOR_WriteProcessMemory_6d7b {
  strings:
    $key_6d7b = { 3a 09 [2] 08 2b [2] 0e 1e [2] 20 1e [2] 1f 02 }

  condition:
    any of them
}