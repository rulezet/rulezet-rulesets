rule TTP_XOR_WriteProcessMemory_007b {
  strings:
    $key_007b = { 57 09 [2] 65 2b [2] 63 1e [2] 4d 1e [2] 72 02 }

  condition:
    any of them
}