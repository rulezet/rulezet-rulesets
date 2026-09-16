rule TTP_XOR_WriteProcessMemory_25e4 {
  strings:
    $key_25e4 = { 72 96 [2] 40 b4 [2] 46 81 [2] 68 81 [2] 57 9d }

  condition:
    any of them
}