rule TTP_XOR_WriteProcessMemory_6fe6 {
  strings:
    $key_6fe6 = { 38 94 [2] 0a b6 [2] 0c 83 [2] 22 83 [2] 1d 9f }

  condition:
    any of them
}