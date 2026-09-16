rule TTP_XOR_WriteProcessMemory_e7ed {
  strings:
    $key_e7ed = { b0 9f [2] 82 bd [2] 84 88 [2] aa 88 [2] 95 94 }

  condition:
    any of them
}