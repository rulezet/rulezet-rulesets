rule TTP_XOR_WriteProcessMemory_2bd8 {
  strings:
    $key_2bd8 = { 7c aa [2] 4e 88 [2] 48 bd [2] 66 bd [2] 59 a1 }

  condition:
    any of them
}