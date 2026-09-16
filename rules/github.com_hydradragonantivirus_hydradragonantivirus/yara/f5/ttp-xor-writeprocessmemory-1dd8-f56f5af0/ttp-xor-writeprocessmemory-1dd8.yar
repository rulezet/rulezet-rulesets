rule TTP_XOR_WriteProcessMemory_1dd8 {
  strings:
    $key_1dd8 = { 4a aa [2] 78 88 [2] 7e bd [2] 50 bd [2] 6f a1 }

  condition:
    any of them
}