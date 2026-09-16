rule TTP_XOR_WriteProcessMemory_e2d8 {
  strings:
    $key_e2d8 = { b5 aa [2] 87 88 [2] 81 bd [2] af bd [2] 90 a1 }

  condition:
    any of them
}