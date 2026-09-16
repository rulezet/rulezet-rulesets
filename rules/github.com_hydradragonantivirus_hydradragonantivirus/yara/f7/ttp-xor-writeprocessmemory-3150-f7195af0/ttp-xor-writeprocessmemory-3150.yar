rule TTP_XOR_WriteProcessMemory_3150 {
  strings:
    $key_3150 = { 66 22 [2] 54 00 [2] 52 35 [2] 7c 35 [2] 43 29 }

  condition:
    any of them
}