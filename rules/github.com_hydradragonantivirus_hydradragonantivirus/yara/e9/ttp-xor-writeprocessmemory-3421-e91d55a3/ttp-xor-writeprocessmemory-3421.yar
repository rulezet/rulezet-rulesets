rule TTP_XOR_WriteProcessMemory_3421 {
  strings:
    $key_3421 = { 63 53 [2] 51 71 [2] 57 44 [2] 79 44 [2] 46 58 }

  condition:
    any of them
}