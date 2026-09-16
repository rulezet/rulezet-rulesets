rule TTP_XOR_WriteProcessMemory_0f7b {
  strings:
    $key_0f7b = { 58 09 [2] 6a 2b [2] 6c 1e [2] 42 1e [2] 7d 02 }

  condition:
    any of them
}