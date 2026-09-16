rule TTP_XOR_WriteProcessMemory_ebf6 {
  strings:
    $key_ebf6 = { bc 84 [2] 8e a6 [2] 88 93 [2] a6 93 [2] 99 8f }

  condition:
    any of them
}