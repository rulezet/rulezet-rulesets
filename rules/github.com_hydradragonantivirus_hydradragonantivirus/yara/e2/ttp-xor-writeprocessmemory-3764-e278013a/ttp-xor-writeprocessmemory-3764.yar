rule TTP_XOR_WriteProcessMemory_3764 {
  strings:
    $key_3764 = { 60 16 [2] 52 34 [2] 54 01 [2] 7a 01 [2] 45 1d }

  condition:
    any of them
}