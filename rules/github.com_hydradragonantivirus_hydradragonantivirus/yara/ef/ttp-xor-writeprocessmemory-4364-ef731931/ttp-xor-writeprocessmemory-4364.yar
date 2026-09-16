rule TTP_XOR_WriteProcessMemory_4364 {
  strings:
    $key_4364 = { 14 16 [2] 26 34 [2] 20 01 [2] 0e 01 [2] 31 1d }

  condition:
    any of them
}