rule TTP_XOR_WriteProcessMemory_5364 {
  strings:
    $key_5364 = { 04 16 [2] 36 34 [2] 30 01 [2] 1e 01 [2] 21 1d }

  condition:
    any of them
}