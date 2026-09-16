rule TTP_XOR_WriteProcessMemory_69d4 {
  strings:
    $key_69d4 = { 3e a6 [2] 0c 84 [2] 0a b1 [2] 24 b1 [2] 1b ad }

  condition:
    any of them
}