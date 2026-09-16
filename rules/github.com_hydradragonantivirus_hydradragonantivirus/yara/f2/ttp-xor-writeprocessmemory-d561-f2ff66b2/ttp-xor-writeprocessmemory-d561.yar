rule TTP_XOR_WriteProcessMemory_d561 {
  strings:
    $key_d561 = { 82 13 [2] b0 31 [2] b6 04 [2] 98 04 [2] a7 18 }

  condition:
    any of them
}