rule TTP_XOR_WriteProcessMemory_6deb {
  strings:
    $key_6deb = { 3a 99 [2] 08 bb [2] 0e 8e [2] 20 8e [2] 1f 92 }

  condition:
    any of them
}