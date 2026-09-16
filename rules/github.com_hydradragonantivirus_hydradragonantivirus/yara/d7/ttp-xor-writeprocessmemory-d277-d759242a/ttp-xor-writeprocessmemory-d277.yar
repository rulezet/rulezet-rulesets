rule TTP_XOR_WriteProcessMemory_d277 {
  strings:
    $key_d277 = { 85 05 [2] b7 27 [2] b1 12 [2] 9f 12 [2] a0 0e }

  condition:
    any of them
}