rule TTP_XOR_WriteProcessMemory_0364 {
  strings:
    $key_0364 = { 54 16 [2] 66 34 [2] 60 01 [2] 4e 01 [2] 71 1d }

  condition:
    any of them
}