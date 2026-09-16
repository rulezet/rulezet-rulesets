rule TTP_XOR_WriteProcessMemory_ddde {
  strings:
    $key_ddde = { 8a ac [2] b8 8e [2] be bb [2] 90 bb [2] af a7 }

  condition:
    any of them
}