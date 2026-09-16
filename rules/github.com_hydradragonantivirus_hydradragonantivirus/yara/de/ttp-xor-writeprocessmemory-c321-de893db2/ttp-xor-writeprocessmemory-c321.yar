rule TTP_XOR_WriteProcessMemory_c321 {
  strings:
    $key_c321 = { 94 53 [2] a6 71 [2] a0 44 [2] 8e 44 [2] b1 58 }

  condition:
    any of them
}