rule TTP_XOR_WriteProcessMemory_cdeb {
  strings:
    $key_cdeb = { 9a 99 [2] a8 bb [2] ae 8e [2] 80 8e [2] bf 92 }

  condition:
    any of them
}