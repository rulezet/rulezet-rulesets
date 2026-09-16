rule TTP_XOR_WriteProcessMemory_ebf0 {
  strings:
    $key_ebf0 = { bc 82 [2] 8e a0 [2] 88 95 [2] a6 95 [2] 99 89 }

  condition:
    any of them
}