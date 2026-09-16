rule TTP_XOR_WriteProcessMemory_c84b {
  strings:
    $key_c84b = { 9f 39 [2] ad 1b [2] ab 2e [2] 85 2e [2] ba 32 }

  condition:
    any of them
}