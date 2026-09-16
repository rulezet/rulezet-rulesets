rule TTP_XOR_WriteProcessMemory_4bfb {
  strings:
    $key_4bfb = { 1c 89 [2] 2e ab [2] 28 9e [2] 06 9e [2] 39 82 }

  condition:
    any of them
}