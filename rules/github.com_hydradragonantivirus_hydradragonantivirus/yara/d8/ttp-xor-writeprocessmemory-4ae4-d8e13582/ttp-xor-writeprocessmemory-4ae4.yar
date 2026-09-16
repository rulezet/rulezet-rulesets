rule TTP_XOR_WriteProcessMemory_4ae4 {
  strings:
    $key_4ae4 = { 1d 96 [2] 2f b4 [2] 29 81 [2] 07 81 [2] 38 9d }

  condition:
    any of them
}