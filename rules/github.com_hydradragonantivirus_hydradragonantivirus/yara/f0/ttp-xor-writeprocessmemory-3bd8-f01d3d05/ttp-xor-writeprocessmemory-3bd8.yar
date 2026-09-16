rule TTP_XOR_WriteProcessMemory_3bd8 {
  strings:
    $key_3bd8 = { 6c aa [2] 5e 88 [2] 58 bd [2] 76 bd [2] 49 a1 }

  condition:
    any of them
}