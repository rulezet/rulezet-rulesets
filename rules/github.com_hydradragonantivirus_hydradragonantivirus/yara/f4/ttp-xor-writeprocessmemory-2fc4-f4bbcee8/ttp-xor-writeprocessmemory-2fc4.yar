rule TTP_XOR_WriteProcessMemory_2fc4 {
  strings:
    $key_2fc4 = { 78 b6 [2] 4a 94 [2] 4c a1 [2] 62 a1 [2] 5d bd }

  condition:
    any of them
}