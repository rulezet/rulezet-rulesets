rule TTP_XOR_WriteProcessMemory_4c7b {
  strings:
    $key_4c7b = { 1b 09 [2] 29 2b [2] 2f 1e [2] 01 1e [2] 3e 02 }

  condition:
    any of them
}