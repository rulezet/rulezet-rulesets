rule TTP_XOR_WriteProcessMemory_0f4b {
  strings:
    $key_0f4b = { 58 39 [2] 6a 1b [2] 6c 2e [2] 42 2e [2] 7d 32 }

  condition:
    any of them
}