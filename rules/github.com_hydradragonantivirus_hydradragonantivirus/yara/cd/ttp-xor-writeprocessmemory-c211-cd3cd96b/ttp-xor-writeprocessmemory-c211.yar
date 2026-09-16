rule TTP_XOR_WriteProcessMemory_c211 {
  strings:
    $key_c211 = { 95 63 [2] a7 41 [2] a1 74 [2] 8f 74 [2] b0 68 }

  condition:
    any of them
}