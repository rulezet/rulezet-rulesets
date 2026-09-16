rule TTP_XOR_WriteProcessMemory_741b {
  strings:
    $key_741b = { 23 69 [2] 11 4b [2] 17 7e [2] 39 7e [2] 06 62 }

  condition:
    any of them
}