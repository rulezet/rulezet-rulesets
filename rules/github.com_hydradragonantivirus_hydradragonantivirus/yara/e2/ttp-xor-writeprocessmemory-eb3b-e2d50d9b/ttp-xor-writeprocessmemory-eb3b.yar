rule TTP_XOR_WriteProcessMemory_eb3b {
  strings:
    $key_eb3b = { bc 49 [2] 8e 6b [2] 88 5e [2] a6 5e [2] 99 42 }

  condition:
    any of them
}