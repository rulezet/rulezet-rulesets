rule TTP_XOR_WriteProcessMemory_e9e7 {
  strings:
    $key_e9e7 = { be 95 [2] 8c b7 [2] 8a 82 [2] a4 82 [2] 9b 9e }

  condition:
    any of them
}