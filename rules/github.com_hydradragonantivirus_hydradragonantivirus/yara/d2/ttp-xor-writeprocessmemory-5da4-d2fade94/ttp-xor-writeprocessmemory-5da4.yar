rule TTP_XOR_WriteProcessMemory_5da4 {
  strings:
    $key_5da4 = { 0a d6 [2] 38 f4 [2] 3e c1 [2] 10 c1 [2] 2f dd }

  condition:
    any of them
}