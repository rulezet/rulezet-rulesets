rule TTP_XOR_WriteProcessMemory_317b {
  strings:
    $key_317b = { 66 09 [2] 54 2b [2] 52 1e [2] 7c 1e [2] 43 02 }

  condition:
    any of them
}