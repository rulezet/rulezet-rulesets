rule TTP_XOR_WriteProcessMemory_ccc0 {
  strings:
    $key_ccc0 = { 9b b2 [2] a9 90 [2] af a5 [2] 81 a5 [2] be b9 }

  condition:
    any of them
}