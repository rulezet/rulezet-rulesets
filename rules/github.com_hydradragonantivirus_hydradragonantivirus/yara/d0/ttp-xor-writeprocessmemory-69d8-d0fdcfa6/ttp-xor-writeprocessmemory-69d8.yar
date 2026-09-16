rule TTP_XOR_WriteProcessMemory_69d8 {
  strings:
    $key_69d8 = { 3e aa [2] 0c 88 [2] 0a bd [2] 24 bd [2] 1b a1 }

  condition:
    any of them
}