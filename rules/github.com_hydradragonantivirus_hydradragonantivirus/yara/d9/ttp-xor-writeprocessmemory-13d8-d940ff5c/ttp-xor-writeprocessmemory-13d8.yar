rule TTP_XOR_WriteProcessMemory_13d8 {
  strings:
    $key_13d8 = { 44 aa [2] 76 88 [2] 70 bd [2] 5e bd [2] 61 a1 }

  condition:
    any of them
}