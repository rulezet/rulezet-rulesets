rule TTP_XOR_WriteProcessMemory_1b6b {
  strings:
    $key_1b6b = { 4c 19 [2] 7e 3b [2] 78 0e [2] 56 0e [2] 69 12 }

  condition:
    any of them
}