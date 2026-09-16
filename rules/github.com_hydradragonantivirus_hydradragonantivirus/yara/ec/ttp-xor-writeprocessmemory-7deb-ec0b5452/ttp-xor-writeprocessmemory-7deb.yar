rule TTP_XOR_WriteProcessMemory_7deb {
  strings:
    $key_7deb = { 2a 99 [2] 18 bb [2] 1e 8e [2] 30 8e [2] 0f 92 }

  condition:
    any of them
}