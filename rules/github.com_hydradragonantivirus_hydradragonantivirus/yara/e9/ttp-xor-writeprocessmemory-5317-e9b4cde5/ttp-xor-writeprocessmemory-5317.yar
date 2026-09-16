rule TTP_XOR_WriteProcessMemory_5317 {
  strings:
    $key_5317 = { 04 65 [2] 36 47 [2] 30 72 [2] 1e 72 [2] 21 6e }

  condition:
    any of them
}