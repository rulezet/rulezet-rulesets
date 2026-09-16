rule TTP_XOR_WriteProcessMemory_4c4b {
  strings:
    $key_4c4b = { 1b 39 [2] 29 1b [2] 2f 2e [2] 01 2e [2] 3e 32 }

  condition:
    any of them
}