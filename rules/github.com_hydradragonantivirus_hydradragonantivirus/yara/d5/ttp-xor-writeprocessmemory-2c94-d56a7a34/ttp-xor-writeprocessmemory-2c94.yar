rule TTP_XOR_WriteProcessMemory_2c94 {
  strings:
    $key_2c94 = { 7b e6 [2] 49 c4 [2] 4f f1 [2] 61 f1 [2] 5e ed }

  condition:
    any of them
}