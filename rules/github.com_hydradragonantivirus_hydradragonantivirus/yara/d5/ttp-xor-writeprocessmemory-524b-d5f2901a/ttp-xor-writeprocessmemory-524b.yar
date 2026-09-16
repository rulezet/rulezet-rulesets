rule TTP_XOR_WriteProcessMemory_524b {
  strings:
    $key_524b = { 05 39 [2] 37 1b [2] 31 2e [2] 1f 2e [2] 20 32 }

  condition:
    any of them
}