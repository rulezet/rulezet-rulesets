rule TTP_XOR_WriteProcessMemory_d410 {
  strings:
    $key_d410 = { 83 62 [2] b1 40 [2] b7 75 [2] 99 75 [2] a6 69 }

  condition:
    any of them
}