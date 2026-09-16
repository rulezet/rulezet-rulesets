rule TTP_XOR_WriteProcessMemory_35d8 {
  strings:
    $key_35d8 = { 62 aa [2] 50 88 [2] 56 bd [2] 78 bd [2] 47 a1 }

  condition:
    any of them
}