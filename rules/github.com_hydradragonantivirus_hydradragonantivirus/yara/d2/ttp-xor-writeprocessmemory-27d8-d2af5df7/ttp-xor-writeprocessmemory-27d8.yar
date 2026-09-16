rule TTP_XOR_WriteProcessMemory_27d8 {
  strings:
    $key_27d8 = { 70 aa [2] 42 88 [2] 44 bd [2] 6a bd [2] 55 a1 }

  condition:
    any of them
}