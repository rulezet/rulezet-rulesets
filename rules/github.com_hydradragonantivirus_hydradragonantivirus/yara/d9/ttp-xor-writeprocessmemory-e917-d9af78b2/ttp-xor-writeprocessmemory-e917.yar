rule TTP_XOR_WriteProcessMemory_e917 {
  strings:
    $key_e917 = { be 65 [2] 8c 47 [2] 8a 72 [2] a4 72 [2] 9b 6e }

  condition:
    any of them
}