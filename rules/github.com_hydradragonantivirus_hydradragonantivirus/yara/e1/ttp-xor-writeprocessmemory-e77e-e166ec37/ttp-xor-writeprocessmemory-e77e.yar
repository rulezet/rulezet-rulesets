rule TTP_XOR_WriteProcessMemory_e77e {
  strings:
    $key_e77e = { b0 0c [2] 82 2e [2] 84 1b [2] aa 1b [2] 95 07 }

  condition:
    any of them
}