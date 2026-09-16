rule TTP_XOR_WriteProcessMemory_2c91 {
  strings:
    $key_2c91 = { 7b e3 [2] 49 c1 [2] 4f f4 [2] 61 f4 [2] 5e e8 }

  condition:
    any of them
}