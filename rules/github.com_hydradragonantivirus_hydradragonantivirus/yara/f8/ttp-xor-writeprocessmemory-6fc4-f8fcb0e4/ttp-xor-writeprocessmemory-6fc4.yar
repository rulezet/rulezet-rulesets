rule TTP_XOR_WriteProcessMemory_6fc4 {
  strings:
    $key_6fc4 = { 38 b6 [2] 0a 94 [2] 0c a1 [2] 22 a1 [2] 1d bd }

  condition:
    any of them
}