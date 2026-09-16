rule TTP_XOR_WriteProcessMemory_e940 {
  strings:
    $key_e940 = { be 32 [2] 8c 10 [2] 8a 25 [2] a4 25 [2] 9b 39 }

  condition:
    any of them
}