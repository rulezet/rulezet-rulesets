rule TTP_XOR_WriteProcessMemory_07d8 {
  strings:
    $key_07d8 = { 50 aa [2] 62 88 [2] 64 bd [2] 4a bd [2] 75 a1 }

  condition:
    any of them
}