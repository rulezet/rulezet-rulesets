rule TTP_XOR_WriteProcessMemory_7ceb {
  strings:
    $key_7ceb = { 2b 99 [2] 19 bb [2] 1f 8e [2] 31 8e [2] 0e 92 }

  condition:
    any of them
}