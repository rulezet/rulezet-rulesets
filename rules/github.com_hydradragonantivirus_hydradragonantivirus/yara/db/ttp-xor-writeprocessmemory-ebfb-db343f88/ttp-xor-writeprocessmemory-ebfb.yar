rule TTP_XOR_WriteProcessMemory_ebfb {
  strings:
    $key_ebfb = { bc 89 [2] 8e ab [2] 88 9e [2] a6 9e [2] 99 82 }

  condition:
    any of them
}