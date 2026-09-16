rule TTP_XOR_WriteProcessMemory_0da4 {
  strings:
    $key_0da4 = { 5a d6 [2] 68 f4 [2] 6e c1 [2] 40 c1 [2] 7f dd }

  condition:
    any of them
}