rule TTP_XOR_WriteProcessMemory_016b {
  strings:
    $key_016b = { 56 19 [2] 64 3b [2] 62 0e [2] 4c 0e [2] 73 12 }

  condition:
    any of them
}