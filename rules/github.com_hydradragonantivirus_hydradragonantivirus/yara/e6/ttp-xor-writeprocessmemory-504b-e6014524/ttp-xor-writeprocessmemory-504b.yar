rule TTP_XOR_WriteProcessMemory_504b {
  strings:
    $key_504b = { 07 39 [2] 35 1b [2] 33 2e [2] 1d 2e [2] 22 32 }

  condition:
    any of them
}