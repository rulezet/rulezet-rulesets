rule TTP_XOR_WriteProcessMemory_6c6b {
  strings:
    $key_6c6b = { 3b 19 [2] 09 3b [2] 0f 0e [2] 21 0e [2] 1e 12 }

  condition:
    any of them
}