rule TTP_XOR_WriteProcessMemory_2cd8 {
  strings:
    $key_2cd8 = { 7b aa [2] 49 88 [2] 4f bd [2] 61 bd [2] 5e a1 }

  condition:
    any of them
}