rule TTP_XOR_WriteProcessMemory_5432 {
  strings:
    $key_5432 = { 03 40 [2] 31 62 [2] 37 57 [2] 19 57 [2] 26 4b }

  condition:
    any of them
}