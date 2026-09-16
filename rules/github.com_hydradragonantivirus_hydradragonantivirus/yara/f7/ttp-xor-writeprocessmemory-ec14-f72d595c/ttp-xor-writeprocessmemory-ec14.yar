rule TTP_XOR_WriteProcessMemory_ec14 {
  strings:
    $key_ec14 = { bb 66 [2] 89 44 [2] 8f 71 [2] a1 71 [2] 9e 6d }

  condition:
    any of them
}