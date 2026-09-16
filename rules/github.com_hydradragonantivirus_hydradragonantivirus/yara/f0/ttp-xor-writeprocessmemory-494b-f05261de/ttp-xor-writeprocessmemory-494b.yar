rule TTP_XOR_WriteProcessMemory_494b {
  strings:
    $key_494b = { 1e 39 [2] 2c 1b [2] 2a 2e [2] 04 2e [2] 3b 32 }

  condition:
    any of them
}