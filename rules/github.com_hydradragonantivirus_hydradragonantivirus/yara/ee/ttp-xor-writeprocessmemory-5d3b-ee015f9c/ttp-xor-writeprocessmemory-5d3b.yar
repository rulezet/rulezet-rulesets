rule TTP_XOR_WriteProcessMemory_5d3b {
  strings:
    $key_5d3b = { 0a 49 [2] 38 6b [2] 3e 5e [2] 10 5e [2] 2f 42 }

  condition:
    any of them
}