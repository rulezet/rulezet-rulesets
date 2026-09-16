rule TTP_XOR_WriteProcessMemory_424b {
  strings:
    $key_424b = { 15 39 [2] 27 1b [2] 21 2e [2] 0f 2e [2] 30 32 }

  condition:
    any of them
}