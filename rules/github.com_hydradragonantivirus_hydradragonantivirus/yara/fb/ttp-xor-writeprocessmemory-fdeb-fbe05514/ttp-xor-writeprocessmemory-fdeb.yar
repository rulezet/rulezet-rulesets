rule TTP_XOR_WriteProcessMemory_fdeb {
  strings:
    $key_fdeb = { aa 99 [2] 98 bb [2] 9e 8e [2] b0 8e [2] 8f 92 }

  condition:
    any of them
}