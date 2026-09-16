rule TTP_XOR_WriteProcessMemory_ec68 {
  strings:
    $key_ec68 = { bb 1a [2] 89 38 [2] 8f 0d [2] a1 0d [2] 9e 11 }

  condition:
    any of them
}