rule TTP_XOR_WriteProcessMemory_724b {
  strings:
    $key_724b = { 25 39 [2] 17 1b [2] 11 2e [2] 3f 2e [2] 00 32 }

  condition:
    any of them
}