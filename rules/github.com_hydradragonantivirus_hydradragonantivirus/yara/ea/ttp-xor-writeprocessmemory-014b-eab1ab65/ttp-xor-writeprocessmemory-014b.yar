rule TTP_XOR_WriteProcessMemory_014b {
  strings:
    $key_014b = { 56 39 [2] 64 1b [2] 62 2e [2] 4c 2e [2] 73 32 }

  condition:
    any of them
}