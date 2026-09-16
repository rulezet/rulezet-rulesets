rule TTP_XOR_WriteProcessMemory_d571 {
  strings:
    $key_d571 = { 82 03 [2] b0 21 [2] b6 14 [2] 98 14 [2] a7 08 }

  condition:
    any of them
}