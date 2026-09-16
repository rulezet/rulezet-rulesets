rule TTP_XOR_WriteProcessMemory_5132 {
  strings:
    $key_5132 = { 06 40 [2] 34 62 [2] 32 57 [2] 1c 57 [2] 23 4b }

  condition:
    any of them
}