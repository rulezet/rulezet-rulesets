rule TTP_XOR_WriteProcessMemory_ebe1 {
  strings:
    $key_ebe1 = { bc 93 [2] 8e b1 [2] 88 84 [2] a6 84 [2] 99 98 }

  condition:
    any of them
}