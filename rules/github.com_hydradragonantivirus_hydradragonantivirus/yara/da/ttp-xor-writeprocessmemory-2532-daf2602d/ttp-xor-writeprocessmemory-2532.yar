rule TTP_XOR_WriteProcessMemory_2532 {
  strings:
    $key_2532 = { 72 40 [2] 40 62 [2] 46 57 [2] 68 57 [2] 57 4b }

  condition:
    any of them
}