rule TTP_XOR_WriteProcessMemory_c470 {
  strings:
    $key_c470 = { 93 02 [2] a1 20 [2] a7 15 [2] 89 15 [2] b6 09 }

  condition:
    any of them
}