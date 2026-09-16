rule TTP_XOR_WriteProcessMemory_bceb {
  strings:
    $key_bceb = { eb 99 [2] d9 bb [2] df 8e [2] f1 8e [2] ce 92 }

  condition:
    any of them
}