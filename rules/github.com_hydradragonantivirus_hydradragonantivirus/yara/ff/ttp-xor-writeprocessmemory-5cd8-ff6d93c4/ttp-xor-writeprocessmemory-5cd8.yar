rule TTP_XOR_WriteProcessMemory_5cd8 {
  strings:
    $key_5cd8 = { 0b aa [2] 39 88 [2] 3f bd [2] 11 bd [2] 2e a1 }

  condition:
    any of them
}