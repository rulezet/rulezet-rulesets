rule TTP_XOR_WriteProcessMemory_48d4 {
  strings:
    $key_48d4 = { 1f a6 [2] 2d 84 [2] 2b b1 [2] 05 b1 [2] 3a ad }

  condition:
    any of them
}