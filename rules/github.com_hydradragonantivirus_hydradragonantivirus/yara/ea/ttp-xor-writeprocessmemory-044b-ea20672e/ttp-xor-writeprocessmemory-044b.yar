rule TTP_XOR_WriteProcessMemory_044b {
  strings:
    $key_044b = { 53 39 [2] 61 1b [2] 67 2e [2] 49 2e [2] 76 32 }

  condition:
    any of them
}