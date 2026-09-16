rule TTP_XOR_WriteProcessMemory_e73d {
  strings:
    $key_e73d = { b0 4f [2] 82 6d [2] 84 58 [2] aa 58 [2] 95 44 }

  condition:
    any of them
}