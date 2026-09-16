rule TTP_XOR_WriteProcessMemory_544b {
  strings:
    $key_544b = { 03 39 [2] 31 1b [2] 37 2e [2] 19 2e [2] 26 32 }

  condition:
    any of them
}