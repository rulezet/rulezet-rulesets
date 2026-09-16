rule TTP_XOR_WriteProcessMemory_c311 {
  strings:
    $key_c311 = { 94 63 [2] a6 41 [2] a0 74 [2] 8e 74 [2] b1 68 }

  condition:
    any of them
}