rule TTP_XOR_WriteProcessMemory_5232 {
  strings:
    $key_5232 = { 05 40 [2] 37 62 [2] 31 57 [2] 1f 57 [2] 20 4b }

  condition:
    any of them
}