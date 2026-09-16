rule TTP_XOR_WriteProcessMemory_e69c {
  strings:
    $key_e69c = { b1 ee [2] 83 cc [2] 85 f9 [2] ab f9 [2] 94 e5 }

  condition:
    any of them
}