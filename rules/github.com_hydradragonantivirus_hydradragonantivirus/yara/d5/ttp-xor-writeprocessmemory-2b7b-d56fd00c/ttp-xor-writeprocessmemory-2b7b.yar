rule TTP_XOR_WriteProcessMemory_2b7b {
  strings:
    $key_2b7b = { 7c 09 [2] 4e 2b [2] 48 1e [2] 66 1e [2] 59 02 }

  condition:
    any of them
}