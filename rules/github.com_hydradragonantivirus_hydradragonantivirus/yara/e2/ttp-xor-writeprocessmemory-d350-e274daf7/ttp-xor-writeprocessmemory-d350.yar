rule TTP_XOR_WriteProcessMemory_d350 {
  strings:
    $key_d350 = { 84 22 [2] b6 00 [2] b0 35 [2] 9e 35 [2] a1 29 }

  condition:
    any of them
}