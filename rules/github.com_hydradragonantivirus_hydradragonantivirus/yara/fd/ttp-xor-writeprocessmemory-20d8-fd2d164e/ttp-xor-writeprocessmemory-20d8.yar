rule TTP_XOR_WriteProcessMemory_20d8 {
  strings:
    $key_20d8 = { 77 aa [2] 45 88 [2] 43 bd [2] 6d bd [2] 52 a1 }

  condition:
    any of them
}