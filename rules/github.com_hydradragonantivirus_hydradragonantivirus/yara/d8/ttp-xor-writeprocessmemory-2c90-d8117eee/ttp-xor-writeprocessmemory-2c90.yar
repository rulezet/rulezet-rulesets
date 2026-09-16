rule TTP_XOR_WriteProcessMemory_2c90 {
  strings:
    $key_2c90 = { 7b e2 [2] 49 c0 [2] 4f f5 [2] 61 f5 [2] 5e e9 }

  condition:
    any of them
}