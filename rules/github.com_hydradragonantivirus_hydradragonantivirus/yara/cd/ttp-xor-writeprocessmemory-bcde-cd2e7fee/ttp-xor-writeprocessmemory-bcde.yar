rule TTP_XOR_WriteProcessMemory_bcde {
  strings:
    $key_bcde = { eb ac [2] d9 8e [2] df bb [2] f1 bb [2] ce a7 }

  condition:
    any of them
}