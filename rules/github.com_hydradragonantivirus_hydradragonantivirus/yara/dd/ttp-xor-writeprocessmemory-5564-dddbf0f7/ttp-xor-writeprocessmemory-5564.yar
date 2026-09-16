rule TTP_XOR_WriteProcessMemory_5564 {
  strings:
    $key_5564 = { 02 16 [2] 30 34 [2] 36 01 [2] 18 01 [2] 27 1d }

  condition:
    any of them
}