rule TTP_XOR_WriteProcessMemory_c413 {
  strings:
    $key_c413 = { 93 61 [2] a1 43 [2] a7 76 [2] 89 76 [2] b6 6a }

  condition:
    any of them
}