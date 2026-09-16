rule TTP_XOR_WriteProcessMemory_ec46 {
  strings:
    $key_ec46 = { bb 34 [2] 89 16 [2] 8f 23 [2] a1 23 [2] 9e 3f }

  condition:
    any of them
}