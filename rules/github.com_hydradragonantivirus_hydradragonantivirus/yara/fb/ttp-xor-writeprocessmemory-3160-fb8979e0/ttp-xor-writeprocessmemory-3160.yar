rule TTP_XOR_WriteProcessMemory_3160 {
  strings:
    $key_3160 = { 66 12 [2] 54 30 [2] 52 05 [2] 7c 05 [2] 43 19 }

  condition:
    any of them
}