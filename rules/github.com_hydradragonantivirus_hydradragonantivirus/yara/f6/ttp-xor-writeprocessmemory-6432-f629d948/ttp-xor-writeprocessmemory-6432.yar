rule TTP_XOR_WriteProcessMemory_6432 {
  strings:
    $key_6432 = { 33 40 [2] 01 62 [2] 07 57 [2] 29 57 [2] 16 4b }

  condition:
    any of them
}