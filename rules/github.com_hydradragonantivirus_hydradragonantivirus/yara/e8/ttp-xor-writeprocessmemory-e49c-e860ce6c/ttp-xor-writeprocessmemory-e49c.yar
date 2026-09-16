rule TTP_XOR_WriteProcessMemory_e49c {
  strings:
    $key_e49c = { b3 ee [2] 81 cc [2] 87 f9 [2] a9 f9 [2] 96 e5 }

  condition:
    any of them
}