rule TTP_XOR_WriteProcessMemory_247b {
  strings:
    $key_247b = { 73 09 [2] 41 2b [2] 47 1e [2] 69 1e [2] 56 02 }

  condition:
    any of them
}