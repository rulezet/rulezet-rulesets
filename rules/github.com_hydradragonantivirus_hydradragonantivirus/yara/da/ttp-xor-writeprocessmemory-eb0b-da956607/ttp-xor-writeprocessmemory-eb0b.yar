rule TTP_XOR_WriteProcessMemory_eb0b {
  strings:
    $key_eb0b = { bc 79 [2] 8e 5b [2] 88 6e [2] a6 6e [2] 99 72 }

  condition:
    any of them
}