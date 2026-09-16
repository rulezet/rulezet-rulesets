rule TTP_XOR_WriteProcessMemory_2fc5 {
  strings:
    $key_2fc5 = { 78 b7 [2] 4a 95 [2] 4c a0 [2] 62 a0 [2] 5d bc }

  condition:
    any of them
}