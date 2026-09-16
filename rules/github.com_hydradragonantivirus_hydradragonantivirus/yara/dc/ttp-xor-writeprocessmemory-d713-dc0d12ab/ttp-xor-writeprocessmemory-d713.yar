rule TTP_XOR_WriteProcessMemory_d713 {
  strings:
    $key_d713 = { 80 61 [2] b2 43 [2] b4 76 [2] 9a 76 [2] a5 6a }

  condition:
    any of them
}