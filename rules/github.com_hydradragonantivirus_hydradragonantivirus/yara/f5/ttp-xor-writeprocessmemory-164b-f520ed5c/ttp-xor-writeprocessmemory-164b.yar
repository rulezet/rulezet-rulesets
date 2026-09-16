rule TTP_XOR_WriteProcessMemory_164b {
  strings:
    $key_164b = { 41 39 [2] 73 1b [2] 75 2e [2] 5b 2e [2] 64 32 }

  condition:
    any of them
}