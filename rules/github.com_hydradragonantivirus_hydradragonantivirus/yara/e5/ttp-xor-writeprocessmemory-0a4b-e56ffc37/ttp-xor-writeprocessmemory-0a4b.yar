rule TTP_XOR_WriteProcessMemory_0a4b {
  strings:
    $key_0a4b = { 5d 39 [2] 6f 1b [2] 69 2e [2] 47 2e [2] 78 32 }

  condition:
    any of them
}