rule TTP_XOR_WriteProcessMemory_ec45 {
  strings:
    $key_ec45 = { bb 37 [2] 89 15 [2] 8f 20 [2] a1 20 [2] 9e 3c }

  condition:
    any of them
}