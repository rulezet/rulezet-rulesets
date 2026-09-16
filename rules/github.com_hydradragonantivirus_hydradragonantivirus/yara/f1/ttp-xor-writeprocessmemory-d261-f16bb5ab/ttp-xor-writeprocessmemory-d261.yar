rule TTP_XOR_WriteProcessMemory_d261 {
  strings:
    $key_d261 = { 85 13 [2] b7 31 [2] b1 04 [2] 9f 04 [2] a0 18 }

  condition:
    any of them
}