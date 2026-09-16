rule TTP_XOR_WriteProcessMemory_e77c {
  strings:
    $key_e77c = { b0 0e [2] 82 2c [2] 84 19 [2] aa 19 [2] 95 05 }

  condition:
    any of them
}