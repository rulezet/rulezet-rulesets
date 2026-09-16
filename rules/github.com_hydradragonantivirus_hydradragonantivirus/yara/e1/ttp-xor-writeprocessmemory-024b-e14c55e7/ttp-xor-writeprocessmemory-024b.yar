rule TTP_XOR_WriteProcessMemory_024b {
  strings:
    $key_024b = { 55 39 [2] 67 1b [2] 61 2e [2] 4f 2e [2] 70 32 }

  condition:
    any of them
}