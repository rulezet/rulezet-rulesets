rule TTP_XOR_WriteProcessMemory_bfc9 {
  strings:
    $key_bfc9 = { e8 bb [2] da 99 [2] dc ac [2] f2 ac [2] cd b0 }

  condition:
    any of them
}