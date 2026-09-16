rule TTP_XOR_WriteProcessMemory_e76c {
  strings:
    $key_e76c = { b0 1e [2] 82 3c [2] 84 09 [2] aa 09 [2] 95 15 }

  condition:
    any of them
}