rule TTP_XOR_WriteProcessMemory_3140 {
  strings:
    $key_3140 = { 66 32 [2] 54 10 [2] 52 25 [2] 7c 25 [2] 43 39 }

  condition:
    any of them
}