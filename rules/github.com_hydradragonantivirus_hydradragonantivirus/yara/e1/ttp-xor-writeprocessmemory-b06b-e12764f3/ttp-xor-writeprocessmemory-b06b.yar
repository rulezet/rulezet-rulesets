rule TTP_XOR_WriteProcessMemory_b06b {
  strings:
    $key_b06b = { e7 19 [2] d5 3b [2] d3 0e [2] fd 0e [2] c2 12 }

  condition:
    any of them
}