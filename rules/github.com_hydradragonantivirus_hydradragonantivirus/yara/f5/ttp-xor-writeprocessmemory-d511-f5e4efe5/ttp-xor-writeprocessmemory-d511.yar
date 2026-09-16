rule TTP_XOR_WriteProcessMemory_d511 {
  strings:
    $key_d511 = { 82 63 [2] b0 41 [2] b6 74 [2] 98 74 [2] a7 68 }

  condition:
    any of them
}