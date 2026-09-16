rule TTP_XOR_WriteProcessMemory_e9d8 {
  strings:
    $key_e9d8 = { be aa [2] 8c 88 [2] 8a bd [2] a4 bd [2] 9b a1 }

  condition:
    any of them
}