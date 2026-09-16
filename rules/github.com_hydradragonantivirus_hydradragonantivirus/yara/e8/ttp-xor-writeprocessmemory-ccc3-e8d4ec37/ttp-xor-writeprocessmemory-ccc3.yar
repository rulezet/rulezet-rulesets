rule TTP_XOR_WriteProcessMemory_ccc3 {
  strings:
    $key_ccc3 = { 9b b1 [2] a9 93 [2] af a6 [2] 81 a6 [2] be ba }

  condition:
    any of them
}