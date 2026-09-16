rule TTP_XOR_WriteProcessMemory_e9f1 {
  strings:
    $key_e9f1 = { be 83 [2] 8c a1 [2] 8a 94 [2] a4 94 [2] 9b 88 }

  condition:
    any of them
}