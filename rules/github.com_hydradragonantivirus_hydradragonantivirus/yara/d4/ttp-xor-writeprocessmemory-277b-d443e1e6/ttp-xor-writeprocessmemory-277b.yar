rule TTP_XOR_WriteProcessMemory_277b {
  strings:
    $key_277b = { 70 09 [2] 42 2b [2] 44 1e [2] 6a 1e [2] 55 02 }

  condition:
    any of them
}