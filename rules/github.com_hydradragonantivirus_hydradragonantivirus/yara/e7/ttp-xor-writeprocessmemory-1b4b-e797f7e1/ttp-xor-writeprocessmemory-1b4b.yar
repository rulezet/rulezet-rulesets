rule TTP_XOR_WriteProcessMemory_1b4b {
  strings:
    $key_1b4b = { 4c 39 [2] 7e 1b [2] 78 2e [2] 56 2e [2] 69 32 }

  condition:
    any of them
}