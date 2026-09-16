rule TTP_XOR_WriteProcessMemory_316b {
  strings:
    $key_316b = { 66 19 [2] 54 3b [2] 52 0e [2] 7c 0e [2] 43 12 }

  condition:
    any of them
}