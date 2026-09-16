rule TTP_XOR_WriteProcessMemory_e778 {
  strings:
    $key_e778 = { b0 0a [2] 82 28 [2] 84 1d [2] aa 1d [2] 95 01 }

  condition:
    any of them
}