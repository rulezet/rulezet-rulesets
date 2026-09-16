rule TTP_XOR_WriteProcessMemory_fa41 {
  strings:
    $key_fa41 = { ad 33 [2] 9f 11 [2] 99 24 [2] b7 24 [2] 88 38 }

  condition:
    any of them
}