rule TTP_XOR_WriteProcessMemory_ec72 {
  strings:
    $key_ec72 = { bb 00 [2] 89 22 [2] 8f 17 [2] a1 17 [2] 9e 0b }

  condition:
    any of them
}