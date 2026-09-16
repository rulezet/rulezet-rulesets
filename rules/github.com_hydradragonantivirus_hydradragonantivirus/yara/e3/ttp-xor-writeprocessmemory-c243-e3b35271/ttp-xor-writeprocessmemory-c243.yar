rule TTP_XOR_WriteProcessMemory_c243 {
  strings:
    $key_c243 = { 95 31 [2] a7 13 [2] a1 26 [2] 8f 26 [2] b0 3a }

  condition:
    any of them
}