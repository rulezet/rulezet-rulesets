rule TTP_XOR_WriteProcessMemory_5b4b {
  strings:
    $key_5b4b = { 0c 39 [2] 3e 1b [2] 38 2e [2] 16 2e [2] 29 32 }

  condition:
    any of them
}