rule TTP_XOR_WriteProcessMemory_ec84 {
  strings:
    $key_ec84 = { bb f6 [2] 89 d4 [2] 8f e1 [2] a1 e1 [2] 9e fd }

  condition:
    any of them
}