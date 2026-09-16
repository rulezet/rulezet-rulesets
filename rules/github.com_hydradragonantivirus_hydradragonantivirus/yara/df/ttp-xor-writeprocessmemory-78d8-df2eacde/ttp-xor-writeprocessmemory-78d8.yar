rule TTP_XOR_WriteProcessMemory_78d8 {
  strings:
    $key_78d8 = { 2f aa [2] 1d 88 [2] 1b bd [2] 35 bd [2] 0a a1 }

  condition:
    any of them
}