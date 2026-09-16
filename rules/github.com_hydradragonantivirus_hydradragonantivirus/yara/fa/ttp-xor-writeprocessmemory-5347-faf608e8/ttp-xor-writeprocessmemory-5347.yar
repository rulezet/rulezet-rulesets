rule TTP_XOR_WriteProcessMemory_5347 {
  strings:
    $key_5347 = { 04 35 [2] 36 17 [2] 30 22 [2] 1e 22 [2] 21 3e }

  condition:
    any of them
}