rule TTP_XOR_WriteProcessMemory_346b {
  strings:
    $key_346b = { 63 19 [2] 51 3b [2] 57 0e [2] 79 0e [2] 46 12 }

  condition:
    any of them
}