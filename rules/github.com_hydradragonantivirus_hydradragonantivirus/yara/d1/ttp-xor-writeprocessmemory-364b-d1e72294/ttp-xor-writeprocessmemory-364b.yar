rule TTP_XOR_WriteProcessMemory_364b {
  strings:
    $key_364b = { 61 39 [2] 53 1b [2] 55 2e [2] 7b 2e [2] 44 32 }

  condition:
    any of them
}