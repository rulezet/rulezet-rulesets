rule TTP_XOR_WriteProcessMemory_177b {
  strings:
    $key_177b = { 40 09 [2] 72 2b [2] 74 1e [2] 5a 1e [2] 65 02 }

  condition:
    any of them
}