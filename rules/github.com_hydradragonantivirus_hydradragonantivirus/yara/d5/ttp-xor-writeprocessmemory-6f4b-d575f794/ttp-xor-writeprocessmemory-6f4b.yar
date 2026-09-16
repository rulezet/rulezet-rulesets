rule TTP_XOR_WriteProcessMemory_6f4b {
  strings:
    $key_6f4b = { 38 39 [2] 0a 1b [2] 0c 2e [2] 22 2e [2] 1d 32 }

  condition:
    any of them
}