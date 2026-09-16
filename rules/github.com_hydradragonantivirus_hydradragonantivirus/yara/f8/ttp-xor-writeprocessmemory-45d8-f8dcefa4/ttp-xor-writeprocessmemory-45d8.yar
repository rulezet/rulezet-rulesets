rule TTP_XOR_WriteProcessMemory_45d8 {
  strings:
    $key_45d8 = { 12 aa [2] 20 88 [2] 26 bd [2] 08 bd [2] 37 a1 }

  condition:
    any of them
}