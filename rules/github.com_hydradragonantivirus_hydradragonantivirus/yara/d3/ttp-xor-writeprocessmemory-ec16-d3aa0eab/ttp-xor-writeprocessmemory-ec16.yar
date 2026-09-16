rule TTP_XOR_WriteProcessMemory_ec16 {
  strings:
    $key_ec16 = { bb 64 [2] 89 46 [2] 8f 73 [2] a1 73 [2] 9e 6f }

  condition:
    any of them
}