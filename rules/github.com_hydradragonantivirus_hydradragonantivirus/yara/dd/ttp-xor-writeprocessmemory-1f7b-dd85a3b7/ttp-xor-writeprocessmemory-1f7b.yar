rule TTP_XOR_WriteProcessMemory_1f7b {
  strings:
    $key_1f7b = { 48 09 [2] 7a 2b [2] 7c 1e [2] 52 1e [2] 6d 02 }

  condition:
    any of them
}