rule TTP_XOR_WriteProcessMemory_3564 {
  strings:
    $key_3564 = { 62 16 [2] 50 34 [2] 56 01 [2] 78 01 [2] 47 1d }

  condition:
    any of them
}