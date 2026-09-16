rule TTP_XOR_WriteProcessMemory_2ee6 {
  strings:
    $key_2ee6 = { 79 94 [2] 4b b6 [2] 4d 83 [2] 63 83 [2] 5c 9f }

  condition:
    any of them
}