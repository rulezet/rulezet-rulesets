rule TTP_XOR_WriteProcessMemory_ec61 {
  strings:
    $key_ec61 = { bb 13 [2] 89 31 [2] 8f 04 [2] a1 04 [2] 9e 18 }

  condition:
    any of them
}