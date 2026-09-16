rule TTP_XOR_WriteProcessMemory_ebde {
  strings:
    $key_ebde = { bc ac [2] 8e 8e [2] 88 bb [2] a6 bb [2] 99 a7 }

  condition:
    any of them
}